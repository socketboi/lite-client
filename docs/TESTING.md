# Testing

The current reference pair is Xray-core v26.11.9 and Hysteria app/v2.13.0.
The reports below retain the exact versions of each measured checkpoint; older
measurements do not qualify a later reference. Current source scope is in
[XRAY-COMPATIBILITY.md](XRAY-COMPATIBILITY.md) and
[HYSTERIA-COMPATIBILITY.md](HYSTERIA-COMPATIBILITY.md).

### Hysteria reference upgrade — 2026-11-06

The current Hysteria pin is app/v2.13.0 (`ca8fbd8`) with apernet/quic-go
`a10df75c`. The owner accepted its added trust_anchors fingerprint extension.
The C hello is checked against an independent generator executing the actual
quic-go handshake package; spec/data/encoder mutations are rejected. Cookie
insertion bounds follow the live hello, and coalesced close tests cover the
Initial/Handshake/1-RTT AEAD boundary. See
[the Hysteria qualification report](HYSTERIA-COMPATIBILITY.md) for source scope,
the offline gate and reproducible local mixed-load/package checks.

An initial 300-second host run completes 2104 one-MiB duplex transfers and
1315 checked UDP echoes, plus 263 required oversize drops and the two
authentication/pin failures. A corruption control is rejected. The archived
inputs retain their own hashes; later final-build runs must retain new receipts.
These are bounded correctness observations, not speed or native-soak results.

### Xray reference upgrade — 2026-11-05

The behavioral pin for this historical checkpoint was Xray v26.10.31 with REALITY 83f621788ca8 and
Go 1.27.3. A fresh isolated loopback matrix completes 36 SHA-256-checked bulk
cases (1152 MiB), 576 UDP echoes and all four worker identities. The server
requires exactly client version 26.10.31. All 45 TLS closure captures match the
reference's absence of an extra outer TLS record after Vision Direct.

Executable reference checks cover the actual Xray close transition, three Go
transport flow-control sequences and eight HTTP/2 header/trailer-budget cases,
plus the full-size CONTINUATION boundary. On the Mi Router 4A, 18 ownership,
six Vision close and eight header-budget cases pass from temporary binaries;
the binaries are removed afterward. Installed services are unchanged.
The documented Docker image builds successfully, and the complete offline
`make -j4 check-spider-behavior` gate passes, including all four device
cross-builds and ARM64/x86 crypto execution checks. Three isolated behavioral
mutations are rejected by the new regression suites.
See [the compatibility report](XRAY-COMPATIBILITY.md) for before/after evidence
and limits. Earlier hardware reports retain their original references.

Fresh upgraded-reference host v4 and native Mi Router 4A v4 checkpoints each
complete 24 phases/120 connections and pass the existing 100-us first-request
regression criterion. CANCEL/path rates remain diagnostic. The native run takes
372 seconds and retains 371 resource observations, with unchanged boot identity,
configuration and interfaces. RAM has no acceptance threshold. First-request
medians below are destination `io-return-v2` microseconds, candidate/reference:

| Scenario | Host | Mi Router 4A |
| --- | --- | --- |
| bigbody | 249 / 364 | 2171 / 6675 |
| gzbody | 291 / 370 | 2250 / 5838 |
| latebig | 302 / 361 | 2122 / 5756 |
| closeafter | 243 / 402 | 2110 / 6451 |

A separate full-Xray versus protobuf-distribution control validates 20 captures
on `bigbody`/`gzbody`, including opening SETTINGS/window, redirect requests,
probe exits, executable identities and cleanup. The controlled destination keeps
its independent x/net v0.58.0 fixture; its sums are committed, seeded into the
Docker image and hashed in new source manifests. An offline readonly build and
all 90 checkpoint tests pass. These bounded checkpoints are not release approval.

### Upgraded-reference Mi Router 4A throughput — 2026-11-05

A separate REALITY-only matrix uses the same LAN path and byte-checked method
as the earlier two-router stand. Three rounds alternate candidate/reference
order, with three direct-relay controls. Nine phases complete 36 transfers of
128 MiB (4608 MiB), with verified full-stream SHA-256, server receipts, executed
binary hashes, ordered journals, resource-monitor completion and cleanup.
The server accepts only client version 26.10.31. Native reference execution is
the qualified Xray protobuf distribution. Median Mbit/s (three rounds):

| Payload | Streams | Candidate | Xray v26.10.31 | Candidate range | Reference range |
| --- | --- | --- | --- | --- | --- |
| Plain | 1 | 58.5 | 10.6 | 58.5–58.6 | 10.6–10.7 |
| Plain | 4 | 68.1 | 20.6 | 67.9–68.2 | 20.6–20.7 |
| TLS 1.3 | 1 | 875.0 | 815.0 | 872.6–908.1 | 770.3–815.4 |
| TLS 1.3 | 4 | 900.5 | 805.5 | 899.7–902.9 | 795.8–861.0 |

The test takes 658 seconds. Independent replay validates every planned phase,
payload/rate calculation and monitor interval; all three candidate phases
retain the supervisor plus four workers. The web service is restored,
boot/configuration/interfaces match and temporary device files are removed.
RAM observations are diagnostic. Relay controls use userspace copying and are
not a link ceiling. No upgraded-reference AX3000T measurement or internet
throughput guarantee follows. The earlier two-router/Hysteria table below
retains its original references and conditions.

### Upgraded-reference mixed host soak — 2026-11-05

The final bounded run carries concurrent UDP and TCP/TLS workloads for 300
seconds each through full Xray, one-worker LiteClient and four-worker LiteClient.
It completes 2684 byte-checked 8-MiB bulk cases and 42,944 UDP echoes. Each role
retains 152 monitor samples, with a maximum 2.047-second gap, stable expected
process identities and successful shutdown/cleanup. Independent replay checks
hashes, payloads, full role/cycle/mode/stream coverage and monitoring. This is
over 15 minutes of host traffic, not an hours-long device soak or a throughput
comparison. RSS is diagnostic without an acceptance cap or a leak-free claim.

The original mixed run's one-worker UDP timeout remains a retained failure.
A separate five-minute candidate replay passes. The final capture relay removes
the old relay's artificial 15-second idle disconnect; the UDP reply deadline
and payload checks remain unchanged. The final run passes, but that does not
prove the original timeout's cause or constitute a client-side fix for it.

### Controlled UDP lifecycle — 2026-11-05

The versioned `tools/vendorcap/nativeclient/udp_lifecycle.py` control adds
three rounds of baseline/FIN/RST cases for full Xray and LiteClient with one
and four workers. Its 27 cases issue 189 unique nonce-tagged datagrams. All
171 mandatory baseline/recovery/rebind/fresh-source echoes pass; the 18 first
packets after injected transport closes time out for both implementations.
First fault-time replies are descriptive, while every healthy/recovered echo
keeps a mandatory five-second deadline and recovery follows three quiet seconds.

The standalone replay verifies frozen inputs and helper sources, listener/
worker identities, actual FIN/RST flags and nonce bytes on both sides of the
proxy in the lossless PCAP, complete case coverage, recovery timing and process
shutdown. A supervisor-only UDP-readiness check is insufficient: each REALITY
worker binds its own UDP socket. The driver waits for all four owned sockets.
All 111 Python tests pass, including a real worker-socket readiness fixture,
detached-checkout replay and negative evidence cases.

These controls demonstrate reference-consistent fault loss and recovery. They
cannot causally identify the historical mixed-run timeout without its missing
capture, and do not justify changing production retries, timers or close policy.

### Native MIPS mixed load and idle reclamation — 2026-11-05

`native_soak.py`/`native-soak.sh` complete a 1005-second Mi Router 4A run with
one and four workers. Each mode runs two 60-second mixed-load epochs, each
followed by 190 quiet seconds. Across the four epochs, 96 one-MiB HTTP/TLS
downloads and 1536 nonce-checked UDP echoes validate against independent host
journals. The loader runs on the device, so these data are not throughput
comparisons. There are four active minutes; most elapsed time observes expiry.

Every post-idle check has zero session socket descriptors. The one-worker
process has six descriptors before and after both epochs; the supervisor plus
four workers has 28 in aggregate before and after both epochs. Only their
configured listeners remain. There are 486/484 resource observations, stable
PID/start-time identities, complete monitor windows, ordinary client/stand
exits and unchanged boot/configuration/interfaces. Services are never paused.
Memory is diagnostic: sampled RSS peaks are 4068/11076 KiB for one/four workers
(aggregate RSS can count shared pages more than once), with no acceptance cap.

The initial setup's unsafe UUID permissions cause the ordinary client to refuse
startup before load; that failure is retained separately. Staging now uses
mode 0600 and validates native MIPS ELF targets. All 132 Python tests pass,
including real helper socket/echo fixtures, owner-only staging, missing monitor
intervals, process restart and unreclaimed sockets. The archived driver replays
the complete native run without the checkout. This does not establish a
multi-hour hardware soak, every leak's absence or release approval.

### Independent flow fault isolation — 2026-11-05

The versioned `flow_isolation.py` host control completes three rounds across
full Xray and ordinary LiteClient with one/four workers: 27 baseline/FIN/RST
cases. Each case maps four separate upstream connections before injecting a
close into the victim UDP transport. Persistent neighboring UDP, plain TCP and
TLS 1.3 streams continue throughout the victim's quiet/recovery interval.

All 10,649 neighboring exchanges pass (3546 UDP, 3552 plain TCP, 3551 TLS),
without changing application sockets or backend TCP connection identities.
All 63 mandatory victim echoes pass; the 18 first-after-fault requests time
out consistently across the reference and both worker counts. The five-second
deadline covers the complete stream reply, including its header and body.
There are no application request retries. Victim upstream recovery is expected;
the independent neighbor transports remain alive with no FIN/RST on the wire
during observation.

Lossless PCAP, nonce receipts, complete case coverage, frozen helper/input
hashes, all four worker listeners, executable identities and process-group
shutdown validate. The 150 Python tests include negative evidence for hidden
reconnects, missing neighbor progress/replies, shared transports, missing close
flags, capture loss, changed helpers and premature timeouts. A preliminary
complete run is retained separately from the final shared-deadline run. This
is bounded host correctness coverage, not a native throughput or long-soak
result, and it does not identify the historical mixed-run timeout's cause.

### Long native mixed-load profile — preparation, 2026-11-05

`native_soak.py --profile long` uses a distinct v2 plan: two 1800-second
scheduled mixed-load windows for each of one/four workers, with a 190-second
idle reclamation check after each window. Acceptance requires 720 bursts,
2880 byte-checked HTTP/TLS downloads, 46,080 nonce UDP echoes, full monitoring,
stable identities, four zero-session-socket checkpoints and ordinary cleanup.
The device/stand deadlines are 8400/9000 seconds. RAM remains diagnostic.

All 154 Python tests pass, including a complete synthetic long-run evidence
fixture and rejected short duration, missing late burst and incomplete long
monitoring. The previous short v1 schema and analyzer remain supported without
loosening their guards. Preparation/test success is not a completed hardware
soak. A running hardware attempt must be reported as pending until its returned
archive and final receipts validate; the measured short/native and host results
above remain separate evidence.

### Completed long native mixed workload — 2026-11-05

The original frozen Xiaomi Mi Router 4A candidate completes in 7965 seconds:
7200 seconds of scheduled mixed-load windows across one/four workers, plus four
190-second idle reclamation windows. These are periodic bursts, not continuous
maximum-rate saturation. All 720 bursts, 2880 one-MiB HTTP/TLS downloads and
46,080 nonce-checked UDP echoes pass against independent backend journals.

The 3809 one-worker and 3786 four-worker observations retain the same PID/start
identities, with maximum sample gaps of two seconds. All four quiet checkpoints
have zero session socket descriptors. Ready/quiet descriptor totals stay
6/6/6 for one worker and 28/28/28 for the supervisor/four-worker group. Client
and monitor termination receipts, device boot/configuration/interfaces and
stand cleanup validate. Device temporary files are removed after verified
upload; the owned stand is removed after local archive validation.

The original and reviewed archives have verified checksums. Frozen, reviewed
and current analyzers all pass locally, and a separate replay with no checkout
also passes. RAM remains diagnostic: peak sampled aggregate RSS is 9268/16368
KiB and minimum system MemAvailable is 6452/196 KiB for one/four workers.
System counters include the loaders and temporary evidence; aggregate RSS can
count shared pages repeatedly. No RAM floor or RSS cap is applied.

This qualifies the original frozen binary. Later conversion and empty-TLS-copy
fixes have separate host/sanitizer/cross-build evidence and the native follow-up
recorded below; this long run is not reassigned to those binaries.
It is neither a throughput comparison nor approval to deploy LiteClient.

### Native soak evidence audit — 2026-11-05

Six negative fixtures initially pass incorrectly: wrong burst byte counters,
compressed burst scheduling, a burst outside its active window, reversed burst
append order, an unknown monitor role and reentry into an earlier monitor phase.
The analyzer now rejects all six by correlating burst counters/order/timing with
known, ordered monitor phases. Timing uses the same device uptime clock and
the existing three-second monitor allowance; no RAM threshold or new client
latency requirement is introduced.

All 160 Python tests pass. The complete retained 1005-second native short run
also passes the strengthened current analyzer. A running long attempt keeps
its original frozen scripts and evidence; its original analysis must be retained
alongside a separate replay with the reviewed analyzer and its source hash.
Passing this audit alone does not establish hardware completion; the completed
long-run result is recorded separately above.

### Selected host ASan/UBSan suites — 2026-11-05

Fourteen C suites pass with address/undefined-behavior sanitizers and leak
detection: REALITY, VLESS, Vision, VLESS responses, HTTP/2 frames, certificates,
chains, Vision I/O/close, header budgets, tunnel ownership, string prefixes,
fingerprint decoding and the shipped ClientHello. Every suite exits 0 with
nonzero successful checks; executable symbols independently confirm both
sanitizers are linked. No sanitizer report is observed. External shared
libraries and assembly are not fully instrumented; this is host coverage.

The first instrumented builds expose three GCC conversion warnings under
`-Werror`: KeyUsage bit extraction, the fingerprint u16 conditional expression
and the string-prefix conditional expression. Explicit unsigned/result types
remove the warnings while preserving values, errors and wire output. Failed
build logs, the final source manifest and individual execution logs are retained.
The ongoing hardware soak retains its original binary and source receipt.
All programs also build for 32-bit MIPS and AArch64 with Hysteria disabled
and enabled after the final edits. The newly stripped MIPS binary has a
different hash from the running soak input, so that hardware evidence must
remain attributed to its original candidate.

Run in the documented build image with a fresh build directory:

```sh
export CGO_ENABLED=0
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
build=/work/sanitize
names='reality vless vision vresp h2frame cert chain vision-io vision-close headerbudget spider-tunnel prefix fpt fphello'
set --
for name in $names; do set -- "$@" "$build/test-$name"; done
make -j4 BUILD="$build" HYSTERIA=0 \
    CC='cc -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g' \
    EXTRA_CFLAGS=-O1 "$@"
for name in $names; do timeout 180 "$build/test-$name" || exit $?; done
```

This optional diagnostic is separate from ordinary correctness checks and
required cross-target builds. It neither measures speed nor grants release
approval or establishes completion of a running native soak.

A separate live `flow_isolation.py` matrix executes the instrumented tunnel
against full Xray: 27 baseline/FIN/RST cases across the reference and one/four
LiteClient workers. All 10,604 neighboring exchanges and 63 mandatory victim
echoes pass, with 18 reference-consistent first-after-fault timeouts. The
lossless capture, distinct persistent neighbors, input/executable hashes and
ordinary group shutdown validate. All 18 LiteClient logs contain no sanitizer
report; symbol and container-environment receipts confirm instrumentation.
SIGTERM termination does not establish an exit-time LeakSanitizer scan for
these processes; the separate 14 normally exiting C suites cover that mode.

The first live attempt is retained as failed at cleanup. A diagnostic observes
two zombie workers with no descriptors immediately after supervisor exit;
both disappear within 100 ms. `checkpoint_process.py` now waits for the parent
and the entire group, including zombies, within the original shared 15-second
deadline. Forced termination remains a failure through subsequent cleanup.
Two isolated Linux integration fixtures reject premature success for a delayed
or stubborn orphan worker; all 162 Python tests pass. No client close, retry
or protocol behavior changes for this test-runner correction.

### Expanded I/O sanitizers — 2026-11-05

Thirteen further C suites pass ASan/UBSan with leak detection: records,
handshake framing, messages, certificate compression, parallel QUIC receive,
parallel TLS record opening, raw input, stream readers, outgoing queues/poll,
listeners, supervisor and datagram reassembly. Every suite exits 0 and performs
successful checks. The supervisor tests retain their real fork, signals,
respawn, parent-death and complete reaping checks.

The initial record run exposes a real C undefined-behavior case: a null
plaintext pointer reaches a zero-length memory copy. TLS 1.3 and both TLS 1.2
copy paths now skip copying when the plaintext length is zero. Additional
round-trip cases exercise empty CBC, GCM and ChaCha20-Poly1305 records with
the actual suite table, correct content type and one sequence advance per
direction. Positive-length RFC 8448 vectors remain unchanged. This matches
the empty-slice behavior of pinned `vendor/utls/conn.go::halfConn.encrypt`,
including CBC's `copy(dst, payload)`; it changes no protocol defaults.

LeakSanitizer also identifies two lost buffers in the handshake test fixture:
its next `memset` discards the previous dynamically grown plaintext window.
The fixture now uses `lc_client_hs_new`/`lc_client_hs_free`, exercising the
existing production owner cleanup. This finding is not evidence of a client
runtime leak. An explicit unsigned bitmap operand also resolves the instrumented
datagram-reassembly build's conversion warning without changing fragment rules.
Failed logs and the later successful results remain separate.

The complete ordinary `make -j4 check-spider-behavior` gate then exits 0 on
this source: all C suites and 162 Python tests, the certificate/policy and
fingerprint/pin/citation gates, all eight programs on MIPS/AArch64 with
Hysteria disabled/enabled, ARM64/x86 crypto execution and the paired Go/C
close/flow observations. This is a fresh complete result after the null-copy
fix, not a reuse of the earlier full-gate receipt.

These results qualify a later source snapshot than the earlier live sanitizer
matrix and the running hardware soak. Do not transfer those binary receipts
to the later candidate. RAM remains diagnostic, and the completed hardware
result above remains attributed to its original frozen candidate.

### Record-fix candidate native follow-up — 2026-11-05

After the conversion and empty-TLS-copy fixes, the then-current cross-built MIPS
binary completes a separate 1005-second Mi Router 4A run with one/four workers.
Its staged and executed hashes match the current build. Both modes perform
two 60-second mixed-load windows followed by 190 quiet seconds. All 96 one-MiB
HTTP/TLS downloads and 1536 nonce UDP echoes match the backend journals.

All 486/484 monitor observations retain stable PID/start-time identities.
Every quiet checkpoint has zero session sockets, with ready/quiet descriptor
totals 6/6/6 and 28/28/28 for one/four workers. Boot/configuration/interfaces
match, normal client/monitor/stand exits validate, and owned temporary files
are removed after evidence retention. Peak sampled aggregate RSS is 4116/11028
KiB; memory remains diagnostic without an acceptance threshold.

The frozen and current analyzers pass locally, as does detached replay without
the checkout. After the load run finishes, the same device separately executes
the cross-built `test-record`: all 32 checks pass, including RFC 8448 wire bytes,
empty TLS 1.3 input and empty TLS 1.2 CBC/GCM/ChaCha20-Poly1305 round trips.
The ELF32 MIPS test binary is hash-verified and removed afterward. These record
checks execute on the device, not under a host emulator or sanitizer runtime.

This closes native execution coverage for the later fixes. It supplies four
active minutes plus reclamation observation, not a second two-hour soak or
a fresh throughput comparison. The original long run and this follow-up
remain separate source/binary qualifications. Nothing is installed or deployed.

### Service configuration preflight — 2026-11-06

`lc-tunnel --check-config`, appended to either complete CLI form, runs the same
credential/fingerprint/option parsers as startup but skips workers, listeners,
DNS and node connections. The init script invokes it before TCP tuning, procd
registration or interception. The actual running command does not retain the
check flag. The package's binary and init script must move together; an older
binary cannot bypass the new validation step.

Seventeen executable tests cover both build variants, occupied listener ports
and an unreachable node, malformed targets/tables, unsafe UUID/auth permissions,
bad UUID contents, a UUID symlink, empty auth and missing plane support. Service
tests source the real init and invoke the real client with procd/sysctl/firewall
effects recorded by stubs. At this checkpoint invalid configurations caused no effects; valid ones
preserve command/credential-file semantics, with no secret contents in logs.
Removing preflight from an isolated init copy is rejected by six cases, without
changing working sources.

Both FIFO credential cases initially hang before `fstat`. Opening a secret with
`O_NONBLOCK` lets the existing regular-file check refuse them immediately, while
preserving accepted regular-file semantics. The complete standard gate passes,
including these 17 tests, the existing 162 checkpoint tests, all C suites and
four MIPS/AArch64 builds. Eight additional preflight cases execute on the actual
MIPS test device, with both binaries hash-verified before/after and temporary
files removed. These qualify the new validation path; earlier traffic/soak
receipts remain tied to their previous source/binary snapshots.

Two additional package tests bring `check-config` to 19 cases. Both install
recipes are staged, checking exact payload contents, binary/init/fingerprint
bytes and permissions. The credential directory/config use 0700/0600. A separate
staging run uses install macros from the checksum-verified OpenWrt 25.12.5 SDK.

The SDK's `include/package-pack.mk` builds APK's `conffiles_static` only from
files present at package build time. Its `KEEP_$(1)` processing also generates
`/lib/upgrade/keep.d/<package>` for conffiles absent from the payload, including
the owner-created credentials. The test router's `/sbin/sysupgrade` reads both
sources. Reviewing the install function alone missed this later SDK step; the
temporary duplicate keep-list installation was removed. The host tests check
the install payload and declaration, not the complete SDK packaging lifecycle.

### Actual APK installation and upgrade — 2026-11-06

Both MIPS variants are built by the pinned OpenWrt 25.12.5 SDK in a separate
Docker volume, as its non-root build user. The existing prepared SDK is copied;
source preparation is cleaned before compiling. Local signing is disabled:
no signing keys or trust roots are generated. The resulting APKs are 428,180
bytes (REALITY) and 672,462 bytes (with Hysteria).

`make check-package` adds an explicit qualification outside the normal host/cross
gate. The SDK's APK tool installs both actual artifacts with their real local
dependency packages, without network or package scripts, in fresh disposable
roots. A synthetic 0.0.9 package is then replaced by the actual 0.1.0 APK:
owner-modified config remains intact, the new default is saved as `.apk-new`,
late-created UUID/auth/obfs retain their bytes and 0600 permissions, and managed
binary/init/fingerprint bytes match the extracted current APK. The credential
directory remains 0700. Metadata checks cover package name/version, MPL-2.0,
MIPS architecture, the config checksum list and the SDK-generated per-package
keep list for the three absent credential files.
The qualification passes both as root and as the unprivileged SDK build user;
the latter uses APK's usermode database. Current APK copies and JSON receipts
remain beside the disposable roots for review.

Both installed MIPS binaries execute under qemu with their installed libraries.
`--planes` distinguishes the variants, `--version` retains the checkout stamp,
and REALITY/Hysteria configuration checks succeed without a node connection.
This qualifies package-manager file behavior and the packaged executables,
not historical-client migration, procd/firewall hooks, firmware sysupgrade or
hardware execution. Nothing is installed on a router.

### Service lifecycle and client selection — 2026-11-06

Five additional cases bring the host config/package gate to 24. Invalid IPv6,
oversized prefixes, malformed IPv4 and trailing-dot IPv4 clients are refused
before TCP tuning or preparing a procd instance. Client validation is shared
with the rule builder; empty lists and valid IPv4/prefix lists remain accepted.

`check_service.py`, included in `make check-package`, executes the SDK's actual
`rc.common` with UCI/procd/kernel commands simulated. Nine lifecycle scenarios
cover publication order and triggers, repeated stop, direct start/reload/restart
with disabled or invalid configuration, and route/nft installation failures.
The prior direct-start behavior reproduces stale interception: `rc_procd`
publishes an empty service even after `start_service` refuses, dropping the old
instance while its interception remains. Every start now removes its previous
interception before reading the new configuration. Accordingly rejected starts
perform cleanup only, without TCP tuning or preparing a new instance; this
supersedes the earlier no-effects assertion above.

`procd_close_instance` only prepares JSON; the service is published after
`start_service` returns. Firewall-error diagnostics no longer infer liveness
from `pgrep` during preparation. The gate checks rollback of owned rules and
preservation of unrelated simulated state. It qualifies real shell lifecycle
control flow, not daemon acceptance, listener readiness or kernel nft behavior.

### Real kernel rollback qualification — 2026-11-06

`check-kernel-rollback` executes the real init functions with iproute2 6.15.0
and nftables 1.1.3 in a Docker namespace containing only loopback, with NET_ADMIN
and IPv6 enabled locally. Nine cases cover empty/repeated teardown, multiple
IPv4/IPv6 rules across legacy table numbers, rejected clients, route installation
failure, nft transaction failure, external marking and repeated failures. Route
and nft faults are injected at the command boundary. Actual kernel queries verify
that no owned rule, route or table remains, and unrelated IPv4/IPv6 policy rules,
routes and a separate nft table stay byte-for-byte equivalent as JSON.

The local kernel (`6.18.54.1-microsoft-standard-WSL2`) rejects `socket transparent`
with ENOENT. Its real failure path rolls back correctly, but successful TPROXY
installation is not qualified here. `check-kernel-tproxy` requires that additional
result and fails on this host (the Python probe returns 77). The rollback receipt
records `tproxy_installation_validated: false`; it is not an interception or
throughput acceptance. No daemon, packet forwarding or device installation is
involved. The Docker namespace is discarded after each run.
Isolated mutations retaining an owned route, retaining the nft table, or skipping
cleanup after transaction failure are all rejected by actual kernel-state checks;
the working init script is unchanged throughout.

### OpenWrt guest TPROXY installation — 2026-11-06

`check-vm-tproxy` closes the successful-installation gap left by the host kernel.
QEMU TCG boots the checksum-pinned official OpenWrt 25.12.5 x86 kernel/rootfs,
with matching 6.12.94 nf/nft socket and TPROXY modules, iproute2 6.18.0 and
nftables 1.1.6. All nine external artifacts have fixed SHA-256 inputs. No disks,
network adapters, KVM, host NET_ADMIN, procd or SSH are involved. A dedicated
PID 1 runs the current init functions and shuts the guest down.

Eight JSON snapshots (baseline plus seven cases) qualify TCP-only, TCP/UDP with
two clients, repeated installation without duplicate policy rules, external
marking with an IPv6 node exemption, teardown/repeated teardown and rollback
of an injected invalid nft transaction. Host-side checks verify rule counts,
transparent socket matches, TPROXY ports, matching packet/policy marks, the
local route, absence of owned state after cleanup and preservation of unrelated
IPv4/IPv6 policy rules/routes plus a separate nft table and chain.

The guest must emit one successful completion, use the pinned kernel version,
exit before the timeout and produce all expected snapshots. QEMU exit status
alone cannot pass the gate. Source/cache changes invalidate the receipt. The
result qualifies successful kernel installation on this x86 guest; it does not
qualify traffic forwarding, a running LiteClient/procd instance, MIPS hardware,
performance or production deployment.
Isolated mutations changing the TCP destination port or reusing the unrelated
fixture's mark are rejected by host snapshot analysis even though the guest
commands and shutdown succeed. A corrupted cached kernel is rejected before
boot. Qualification refuses optimized Python, which would disable assertions.

### Actual service/upgrade VM qualification — 2026-11-06

`make check-vm-service` adds real procd PID 1, ubus, rc.common and SDK APK hooks
to the pinned OpenWrt guest. A veth LAN and backend live entirely inside the
guest; IPv4 forwarding is disabled so successful LAN traffic must cross the
transparent listener and reference node. Fresh random nonces, exact echo bytes
and independent backend SHA-256 receipts qualify TCP, inner TLS and UDP/443.
The fixture explicitly selects `xtls-rprx-vision-udp443`; default Vision correctly
blocks UDP/443, as `vendor/Xray-core/proxy/vless/outbound/outbound.go::Handler.Process`
does. The production flow default is unchanged.

The controlled predecessor uses a real REALITY-only executable under the full
package's name at version 0.0.9. The actual full APK must replace the supervisor
and every worker, even with unchanged UCI/argv. Scenarios include one/four-worker
supervisor SIGKILL and respawn, reload, disabled/invalid starts, foreign listeners,
automatic bind recovery, stop and blocked traffic before/after the service.
Valid startup failures retain interception and procd retries. Readiness checks
socket inode ownership, not just a port or process name. Direct workers are
located by `PPid` in proc status; OpenWrt need not enable the task/children file.

The first boot calls actual `sysupgrade -b`; host analysis requires the config
and all three default secret files with matching hashes and mode 0600. A second
fresh boot installs the actual package, calls `sysupgrade -r`, compares restored
file hashes and verifies fresh traffic. This tests configuration backup/restore
across boots, not flashing an image, physical router reboot, throughput or a
historical released-package migration. Both boots remain diskless with no
external NICs. Sources, packages, inputs, states and receipts are frozen by hash;
fixture credentials and archives remain in private ignored artifacts.

The host `check-config` gate passes 44 cases, including real Linux socket-inode
ownership, unrelated same-executable processes, direct children and start status.
`check_service.py` also checks that readiness follows service publication and
that rejected starts propagate status 1 through real SDK rc.common.

Readiness additionally requires the socket's registration in its owner's epoll
loop. Host fixtures cover unregistering TCP/UDP sockets, stopped/resumed workers,
and the actual native four-worker supervisor with SIGKILL injected before each
worker's event loop starts. Its retained TCP listener must not count as ready.
The service VM also freezes the replacement loop, kills its workers in TCP-only
mode, requires start failure and request timeouts with interception retained,
then resumes the supervisor and checks recovery and UDP restoration. A backend
snapshot before resume must contain none of those probes. TCP bytes retained in
the shared listener's kernel backlog may arrive after recovery; any such receipt
must match the timed-out request and prove forwarding through the node, rather
than treating a client timeout as proof that queued bytes were discarded.

Fingerprint preflight cases cover FIFOs with/without a writer, a symlink to a
FIFO, a device and a directory. Regular-file symlinks remain accepted. A real
stdio fault stream returns a complete valid fingerprint followed by EIO; this
must fail rather than accepting the valid prefix. The C argument suite also
checks exact-capacity and zero-capacity regular-file reads.
The actual packaged MIPS executables reject fingerprint FIFOs with/without a
writer under qemu as well. APK/lifecycle qualification refuses optimized Python
before any work, so `-O` cannot silently disable its assertions.

### Native LAN throughput method — 2026-11-05

The byte-checked bulk-download stand runs an external loader and the pinned
reference servers on one Linux LAN host. Each temporary router client forwards
the same fixed destination; no SSH tunnel carries load traffic. One stream
downloads 128 MiB; four simultaneous streams download 32 MiB each. Every stream
checks its complete SHA-256 and a matching server receipt. Reported Mbit/s counts
delivered download bytes once, divided by elapsed bulk time; TCP and application
TLS handshakes are excluded. Plain payload and TLS 1.3 payload are separate cases.
TLS payload can exercise Vision's direct-copy path; plain payload cannot.
The exclusion refers to loader-side handshakes. A lazy upstream dial can still
fall inside a plain case's timer; these measurements do not isolate handshake
latency. All executables and journals are staged in tmpfs on the routers. A
larger reference executable therefore consumes additional RAM in this setup;
do not turn these results into a claim about a differently installed system.

Three rounds alternate C/reference order separately for REALITY and Hysteria.
Raw TCP relay controls bracket both planes, using the same router and LAN path.
The relay copies in userspace, so its CPU cost can make it slower than a Vision
path using kernel splice; its rate is not a physical link ceiling. The existing
router socket settings and normal services remain in use. Only the isolated
4A's web service is paused temporarily to free an already-allowed input port;
the cleanup path restores it. Routes, firewall, UCI and installed clients are
not replaced. AX3000T uses an independent LAN listener without stopping services.

Xray uses the pinned native protobuf reference distribution built with Go
1.27.1, while Hysteria uses the full pinned app built with Go 1.26.6 and quic-go
`73339f7e`. Candidate binaries are the fresh checked MIPS/AArch64 builds. All
roles use the device's default CPU allocation; no Go or client RAM cap is set.
RAM observations remain diagnostic under the flash-only policy. These are LAN
component measurements, not internet performance guarantees or a long soak.

The first incomplete attempt exposed an observer race on disappearing `/proc`
entries and an ancestry-accounting error. It is retained separately and is not
pooled into the final matrix. The replacement native observer ignores entries
that disappear during its snapshot and sums only the requested process tree;
60 stress snapshots verify ownership while other processes start and exit.
A separate pre-workload connection refusal is also retained; it transferred no
measured payload. Each measured run freezes its exact scripts, configurations,
executables and plan before workload starts.

The completed matrix validates all 15 phases/60 cases on each router, 15 GiB of
measured payload in total. Both drivers and the stand exit 0, all monitors stop
with the expected status, and boot identity, configuration hashes and interface
names match before/after. The 4A web service is restored; AX3000T services remain
running. Elapsed driver time is 2114 seconds on 4A and 202 seconds on AX3000T.
Minimum observed MemAvailable is 0/2748 KiB respectively, with no RAM acceptance
threshold. These values include tmpfs executable staging.

Each rate below is median **[minimum–maximum]** Mbit/s across three rounds.
The plain and TLS rows are distinct workloads, with 128 MiB total per case.

| Router | Plane | Payload | Streams | lite-client | Pinned reference |
| --- | --- | --- | --- | --- | --- |
| 4A | REALITY | plain | 1 | 58.6 [58.6–58.9] | 10.6 [10.5–10.6] |
| 4A | REALITY | plain | 4 | 68.1 [67.7–68.4] | 20.7 [20.7–20.7] |
| 4A | REALITY | TLS 1.3 | 1 | 860.4 [54.5–900.5] | 762.2 [757.4–817.4] |
| 4A | REALITY | TLS 1.3 | 4 | 895.7 [862.0–902.9] | 858.3 [837.3–869.3] |
| 4A | Hysteria2 | plain | 1 | 52.0 [49.4–53.7] | 11.5 [11.5–11.8] |
| 4A | Hysteria2 | plain | 4 | 49.9 [47.5–50.5] | 11.3 [11.1–11.3] |
| 4A | Hysteria2 | TLS 1.3 | 1 | 50.6 [49.4–50.7] | 11.5 [11.4–11.7] |
| 4A | Hysteria2 | TLS 1.3 | 4 | 48.2 [48.1–49.0] | 11.6 [11.2–11.7] |
| AX3000T | REALITY | plain | 1 | 501.2 [466.8–519.5] | 456.5 [358.9–458.3] |
| AX3000T | REALITY | plain | 4 | 611.1 [578.9–619.3] | 645.0 [628.6–750.0] |
| AX3000T | REALITY | TLS 1.3 | 1 | 906.6 [897.6–911.8] | 900.7 [899.4–907.7] |
| AX3000T | REALITY | TLS 1.3 | 4 | 905.9 [814.6–921.0] | 917.6 [916.9–917.7] |
| AX3000T | Hysteria2 | plain | 1 | 336.3 [330.8–340.4] | 233.4 [211.8–271.3] |
| AX3000T | Hysteria2 | plain | 4 | 307.6 [292.4–314.7] | 292.6 [203.1–304.4] |
| AX3000T | Hysteria2 | TLS 1.3 | 1 | 321.6 [310.8–341.7] | 287.8 [213.1–297.3] |
| AX3000T | Hysteria2 | TLS 1.3 | 4 | 296.0 [295.6–303.8] | 287.8 [280.7–290.1] |

The candidate's single-stream REALITY TLS rounds on 4A are 54.5, 900.5 and
860.4 Mbit/s. The slow round is retained; its cause is not established by this
stand, and the median must not be presented as stable near-gigabit performance.
The controls use a user-copy relay: 4A plain single-stream rates are
450.5–502.7 Mbit/s, compared with 870.9–886.4 Mbit/s on AX3000T. Different
copy paths explain why a control cannot be used as a physical link ceiling.

### Executable checkpoint validation — 2026-11-05

Host v4 and native v4 now have executable preparation, runner and evidence
validation tools. Plans freeze the exact binaries, configurations, driver and
analyzers before execution. The native runner additionally records configuration
hashes and requires the resource monitor's expected termination status; complete
samples cannot excuse a failed monitor. Owned-process cleanup also runs on
SIGTERM/HUP. Listener readiness must belong to the launched executable.
See the [checkpoint workflow](../tools/vendorcap/nativeclient/README.md#executable-checkpoint-workflow).

The complete `make check-spider-behavior` gate exits 0: MIPS32 and AArch64 builds
with both Hysteria configurations, QEMU crypto and the controlled C/Go close
oracle all pass. The final checkpoint gate passes shell syntax validation and
86 analyzer/plan/process tests with networking disabled. Runtime C sources,
protocol defaults and fingerprints are unchanged.

The fresh ordinary host checkpoint completes all 24 phases/120 connections
with matching executed-binary hashes, valid wrong-key probe exits and successful
client/stand cleanup. All four scenarios pass the frozen 100-us regression
budget. Rates remain diagnostic under the 3 November policy.

| Scenario | C/Go CANCEL | C/Go selected harvested paths | C/Go first HEADERS median, us | Regression, us |
| --- | --- | --- | --- | --- |
| bigbody | 9/15 / 4/15 | 0/15 / 0/15 | 300 / 313 | 0 |
| gzbody | 0/15 / 2/15 | 0/15 / 0/15 | 317 / 301 | 16 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 314 / 318 | 0 |
| closeafter | 0/15 / 0/15 | 11/15 / 12/15 | 223 / 334 | 0 |

An earlier complete host trial used previously prepared binaries stamped
`unknown`; it is retained separately from this fresh build. A Docker backend
restart interrupted a subsequent host trial and a 17-phase native prefix.
Another native prefix was explicitly stopped after 15 phases to add mandatory
monitor-exit validation. Neither incomplete native attempt is accepted or
pooled with a later run. Their frozen inputs, raw logs and failure results remain
retained. A subsequent native v3 trial stopped after 16 completed phases when
MemAvailable reached 4088 KiB, below that plan's frozen 4096-KiB floor. Its
analyzer rejects it; that historical result is unchanged. The owner then clarified
that flash is the only size constraint. New native v4 plans therefore record RAM
without an acceptance floor/cap; low-memory samples, including zero available
memory, do not reject otherwise complete valid evidence. Process failure and
incomplete execution still fail. No client protocol or memory behavior changes.

The first flash-only v4 run completes all 24 phases but its analyzer rejects
missing startup samples: hashing the reference executable on MIPS takes about
seven seconds before the old monitor launch. The corrected driver starts
sampling before hashing. That rejected run retains its frozen sources and logs;
observation-coverage checks are unchanged.

The corrected native v4 run on Mi Router 4A completes 24 phases/120 connections
in 368 seconds. Device, monitor, stand and cleanup results validate; executed
binary hashes and boot/configuration/interface identity match. Both device and
stand exit 0. Sampling includes executable hashing and covers every observed
phase. `checkpoint_criteria_met` is true with `resource_policy: flash-only` and
`memory_acceptance_threshold: null`.

| Native scenario | C/Go CANCEL | C/Go selected harvested paths | C/Go first HEADERS median, us | Regression, us |
| --- | --- | --- | --- | --- |
| bigbody | 15/15 / 14/15 | 0/15 / 0/15 | 2344 / 5966 | 0 |
| gzbody | 0/15 / 0/15 | 0/15 / 0/15 | 2147 / 5985 | 0 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 2290 / 6066 | 0 |
| closeafter | 0/15 / 0/15 | 11/15 / 11/15 | 2179 / 5791 | 0 |

Six corruptions of an isolated copy of this actual evidence are rejected at the
intended checks: deadline, failed monitor, altered frozen input, incomplete
progress, invalid negative memory counter and changed opening SETTINGS. All
eight controls pass and the retained evidence hashes remain unchanged. Zero
available memory is valid diagnostic data, covered separately by unit tests.
The raw archive transfer is verified by SHA-256. Nothing is installed on flash;
installed services and routing are unchanged. These results
grant bounded checkpoint scope only; no mixed-workload soak or release is claimed.

Fresh stripped standalone binaries satisfy the documented 1.5-MB flash target:
MIPS REALITY/Hysteria are 921,732/1,449,108 bytes; AArch64 are
788,440/1,116,240 bytes. These checks use the pinned cross-toolchain strip tools
on copies, preserving executed binaries. They do not measure SDK package size
or assert that missing target dependencies cost no flash.

These checkpoints are bounded observations, not throughput benchmarks,
mixed-workload soak results or a production release decision.

### Spider correctness policy — 2026-11-03

The owner approved keeping the existing spider while accepting C's permitted
scheduling differences. New host v4/native v3 checkpoints report CANCEL and
selected-path rates without using agreement with Go as acceptance thresholds.
The 100-us nonnegative timing-regression budget, frame/path validation,
provenance, phase completion, probe results and process-stop checks remain.
Native plans keep their memory/duration guards. New reports declare checkpoint
scope rather than a G2Closed release flag. Historical results below and the
frozen Xray-versus-itself calibration retain their original policy and results.

`make check-spider-behavior` runs the full existing check gate followed by the
controlled Go/C close oracle. Checkpoint analyzer tests are now part of `make
check`; build images include Python 3. Plan preparation hashes the exact inputs
and refuses to overwrite an existing plan. The analyzer tests cover extreme
rate differences, the latency boundary, rejected old/mixed schemas, invalid
wire/probes, identities, receipts and cleanup. See
[SPIDER-ACCEPTANCE.md](SPIDER-ACCEPTANCE.md) for commands and scope.

Validation: all 70 analyzer/plan tests pass. Six isolated mutations are rejected:
restoring the rate gate, dropping the latency bound, ignoring an input hash or
client liveness, accepting duplicate CANCEL and accepting missing HEADERS.
Mutation runs leave the working sources unchanged.

The complete `make check-spider-behavior` gate passes in the documented Docker
build environment: all programs cross-build for MIPS little-endian and AArch64
with Hysteria both disabled and enabled, the AArch64/x86 QEMU crypto checks pass,
and all three controlled C/Go close cases match. The final analyzer-only gate
passes all 70 tests in the same image with networking disabled. These are build
and host/QEMU checks; no device trial or production deployment was performed.

This increment changes no runtime C source, fingerprint, retry, port, default
request, TLS behavior or scheduler. A host/checkpoint pass does not establish
native mixed-workload resource acceptance or justify changing archived evidence.

### First LAN read interrupted beside TCP reset - 2026-10-30

Pinned Xray `common/buf/readv_reader.go::ReadVReader.ReadMultiBuffer` uses
`common/buf/reader.go::ReadBuffer` for its first buffer. The TCP reader reaches
Go 1.27.1 `internal/poll/fd_unix.go::FD.Read`, which repeats interrupted reads
through `ignoringEINTRIO`. LiteClient's single-buffer branch instead classified
EINTR alongside EAGAIN. With a simultaneous EPOLLERR/EPOLLHUP, its completion
decision could close the session before consuming the bytes preceding a reset.

`stream_read_first` now retries only EINTR, before read classification, reader
adaptation and Vision framing. `test-vision-io --first-read` adds eight cases
using real loopback TCP and epoll. Only read results are injected: two EINTRs,
or one EAGAIN/EIO. The cases cover a short/full buffer followed by an actual
abortive TCP close, ordinary half-close, EOF and an open connection. They verify
exact payload delivery, preserved unread data on errors and no retry of EAGAIN
or permanent errors. Half-close itself is readable EOF, not LC_EV_ERROR.

The original branch was extracted into the same helper without changing its
single-read behavior for the before/fixed comparison. That version fails on the
interrupted reset case on host, MIPS32/AArch64 QEMU and the test Mi Router 4A.
The fixed complete Vision I/O fixture passes on all four. The 4A runs OpenWrt
24.10.8/kernel 6.6.144; the static cross binaries use the pinned OpenWrt 25.12.5
toolchains and real vendored mbedTLS/zlib archives, not link stubs.

Three isolated mutations fail: losing the EINTR retry, retrying other errors
and retrying after successful data. Mutation checks preserve working source.
ASan/UBSan with leak checks instruments the fixture-included tunnel main and
net/loop.c/net/sock.c; the other linked libraries are ordinary objects. These
are component tests, not a full VPN handshake or throughput comparison.
The full offline `make check` gate passes, including MIPS/AArch64 program
builds with Hysteria disabled/enabled and architecture-specific crypto execution.
Private source identities, binaries and logs are under
`artifacts/lite-client/first-read-20261030`.

### Node transport closes before the client endpoint - 2026-10-30

Pinned Xray `proxy/vless/outbound/outbound.go::Handler.Process` defers the node
Close. `proxy/dokodemo/dokodemo.go::DokodemoDoor.Process` waits for DispatchLink
to finish, and `app/proxyman/inbound/worker.go::tcpWorker.callback` then closes
the inbound socket. uTLS `conn.go::Conn.Close` closes its underlying connection
even if the alert write fails. LiteClient's final teardown previously closed
the LAN socket first; it now finishes the node transport before releasing LAN,
including an expired alert write or an active application write.
The existing G3 retention of failed-handshake sockets remains separate; these
cases exercise transports that close directly rather than enter that collector.

Six additional `test-vision-close` cases observe actual close calls and descriptor
ownership at the close boundary. They cover ordinary completion, parked-reader
backpressure, deadline expiry and a pending application write with stream
socket pairs, plus TLS 1.3/TLS 1.2 over real IPv4 loopback TCP. The preceding twelve
cases remain controls. The preceding runtime fails all six new cases. Tests check
local close order and peer alert/EOF semantics; they do not assert packet arrival
order across two network paths. The process still owns sessions until batch reap.

All eighteen scenarios pass on host and on static MIPS32/AArch64 builds under
QEMU with real vendored mbedTLS/zlib. Four isolated mutations are rejected:
client-first teardown, skipped node close, skipped client close and double node
close. ASan/UBSan instruments fixture-included main.c plus net/loop.c and net/sock.c;
other linked library objects are ordinary builds. The same MIPS binary passes on
the isolated Mi Router 4A Gigabit (OpenWrt 24.10.8, kernel 6.6.144), with the prior
30-second/24-MiB/10-CPU-second runner. Boot ID, UCI, interface names and IPv4 routes
are preserved; the evidence is retrieved and the temporary directory removed.
These are component checks rather than an end-to-end VPN/performance comparison.

Private evidence is retained in `artifacts/lite-client/close-order-20261030`.

### Resumable TLS close_notify - 2026-10-30

Pinned uTLS `conn.go::Conn.Close/closeNotify` writes one warning alert with a
five-second write deadline before closing the transport. Xray's VLESS outbound
defers that Close from Process. A single nonblocking write was insufficient:
LiteClient could lose the alert on EINTR/EAGAIN or truncate it after a short write.
The existing output queue now retains that one sealed record across WRITE events.
The session, keys and LAN socket remain owned until completion/error/deadline;
unrelated connections keep progressing. Pending application writes retain the
reference's immediate-close rule. The timeout participates in loop sleep and
expiry; closed-session reap waits for final teardown. A parked raw reader is
registered for WRITE with ADD, without MOD/ADD recovery or another alert.

`test-vision-close` is included in `make check`. Its initial twelve cases exercise actual
session allocation/reap, epoll and nonblocking socket pairs: TLS 1.3/TLS 1.2 alert
authentication and EOF, repeated EINTR, partial write, real socket backpressure,
parked reader ownership, independent connection progress, fixed deadline,
zero/hard write errors, peer close, active application write and early failure.
Only time and selected write results are controlled. The exact preceding runtime
fails four cases and passes eight controls. Six mutations are rejected on isolated
copies: dropped backpressure, reset deadline, premature reap, wrong budget,
late expiry and MOD on a parked reader. ASan/UBSan instruments fixture-included
main.c plus net/loop.c and net/sock.c; other library objects are ordinary builds.
The main-loop branch routing closing node events is also source-reviewed.

Static fixtures use real vendored mbedTLS/zlib and pass on MIPS32/AArch64 QEMU.
On the isolated Mi Router 4A Gigabit (OpenWrt 24.10.8, kernel 6.6.144), the new
close fixture and the current Vision I/O/carry fixture both exit zero. The runner
limits each process group to 30 seconds, 24 MiB address space and 10 CPU seconds.
Boot ID, UCI export, interface names and IPv4 routes remain unchanged. This is
native component execution, not an end-to-end VPN or performance measurement.
Private source snapshots, binaries, baseline/mutation/sanitizer logs and retrieved
device evidence are in `artifacts/lite-client/close-notify-20261030`.

### Vision buffered-to-raw ordering and reader ownership - 2026-10-30

Pinned `proxy/proxy.go::VisionReader.ReadMultiBuffer` merges TLS input/rawInput
into its returned MultiBuffer. `proxy/vless/encoding/encoding.go::XtlsRead` writes
that buffer before its next iteration calls CopyRawConnIfExist. A blocked older
write therefore prevents the next raw socket read, including observing EOF/error.

`raw_carry` previously filled the available queue space once and then flushed.
If Flush emptied that queue, an unqueued tail could remain with no writer event
to resume it. `direct_pump` could then read newer bytes first. It now resumes the
tail when Flush creates room and defers the raw reader until older queued bytes
finish. Rearm follows the same predicate. A node watch with no runnable raw read
or uplink write is removed while the writer is blocked or node EOF is consumed:
ERR/HUP arrive even for an empty epoll interest mask. An uplink writer restores
its watch; the idle reader can park again. Already-returned node events are ignored
while parked, since DEL cannot retract the current event batch. Existing timers
and error handling for a runnable uplink writer remain in place.

Ten added `test-vision-io` scenarios use real nonblocking sockets, queues, epoll,
copy and Linux splice. A known changing tail exceeds initial free queue space;
with no later input it must finish without another node event. Backpressure cases
retain later bytes/FIN in the node socket, reject readiness spinning, and verify
uplink writes still progress. Two cases fully close the peer while the old writer
is blocked to exercise unconditional HUP. The final peer observes prefill, older
queue, the complete tail and newer bytes exactly once and in order. The preceding
runtime fails eight cases; two positive controls pass. Five isolated mutations
are rejected: orphaned tail, early raw read, wrong readiness, lost carry offset,
and retaining an idle HUP watch. Mutations never overwrite working source.

The fixture enters after Vision decoding; it does not simulate a full encrypted
handshake or all main-loop event-batch permutations. The stale-event guard is
also source-reviewed. Native component execution followed in the close_notify
increment above; neither fixture establishes performance acceptance.
Host component execution passes ASan/UBSan with leak checking on fixture-included
main.c plus net/loop.c and net/sock.c; other linked objects are ordinary builds.
Final static MIPS32/AArch64 executions pass through QEMU with real mbedTLS/zlib,
and the full make check gate passes both Hysteria build variants on both targets
plus the architecture-specific crypto execution gates.
Raw sources, failed setup attempts, binaries and validation records are retained
privately under `artifacts/lite-client/vision-carry-20261030`.

### Interrupted REALITY/Vision uplink operations - 2026-10-30

`test-vision-io` exercises the actual stream_take/stream_pump, queue, rearm and
copy/splice functions with real nonblocking stream socket pairs. It is included
in `make check`. Only selected syscall results are injected before side effects.
The reference is pinned Xray ReadVReader.readMulti/BufferToBytesWriter.WriteMultiBuffer
and Go 1.27.1 FD.Read/FD.Writev; Unbihex is not an acceptance oracle.

Eight cases inject EINTR twice at the initial/repeated FIONREAD, empty-queue
probe, filtering/raw MSG_PEEK, raw write and multi/single-buffer drain reads.
All eight fail the new assertions on the exact preceding runtime. Six could
terminate a transfer; the empty probe deferred progress and the raw write
mistook interruption for backpressure. The fixed code retries just that syscall,
preserving the same MultiBuffer, adaptation, raw bytes and write continuation.
Each site also gets a permanent EIO control, which must remain a failure.
A ninth baseline case shows a zero-byte raw write being queued; it is now an
error like the initial zero-progress case in Go Writev. EOF stays distinct.

Two real-EAGAIN scenarios fill the node-facing socket, preserve the queue plus
kernel remainder, and observe downlink readiness and delivery before the peer
drains the upload. Both copy and Linux splice are exercised. Downlink EOF then
leaves all accepted upload bytes intact, and draining the peer produces the
exact prefill plus payload once, in order. These cases do not run a complete
REALITY handshake, measure timing/performance or establish hardware acceptance.

The final fixture passes on host. Five isolated mutations are rejected: missing
peek/drain retry, retrying permanent errors, accepting zero write, and discarding
uplink remainder on downlink EOF. ASan/UBSan with leak checking instruments the
fixture-included main.c plus net/loop.c and net/sock.c; other linked libraries
are ordinary objects, and no broader sanitizer scope is claimed. Mutations use
separate copies and leave working source unchanged. Exact sources, binaries,
before/fixed results and reference files are retained privately under
`artifacts/lite-client/vision-io-20261030`.
Static MIPS32/AArch64 executions pass under QEMU with real vendored mbedTLS/zlib
archives, including both copy and splice cases; link stubs are not executed.
The full offline `make check` gate passes, including both Hysteria variants on
MIPS/AArch64 and the architecture-specific crypto execution gates. This does
not replace a router traffic run or a reference wire/performance experiment.

### Listener recovery after descriptor exhaustion - 2026-10-30

The accept loop removed its TCP listener for 500 ms after EMFILE/ENFILE, following
`vendor/Xray-core/transport/internet/tcp/hub.go::keepAccepting`. It cleared the
retry deadline before re-registering the descriptor. If that epoll ADD failed,
the process stayed alive with no listener watch and no future retry.

`accept_resume` now clears the deadline only after successful registration.
A failed ADD schedules another 500-ms attempt and logs the registration error
once per suspension. Existing session watches stay active, and a shared listener
retains EPOLLEXCLUSIVE on re-registration. This changes recovery from a local
resource failure, not protocol bytes, connection refusal policy or normal timing.

`test-listener`, included in `make check`, uses real loopback TCP, epoll and
process-local RLIMIT_NOFILE exhaustion: an actual queued accept fails with EMFILE.
Only the retry clock and two subsequent ADD failures are controlled. Four cases
cover ordinary/shared listeners and ENOMEM/ENOSPC registration errors. They check
continued established traffic, preserved queued connections, retry deadlines,
earlier event-loop deadlines and no early/duplicate ADD after recovery.
The new fixture passes on host with ASan/UBSan and on static MIPS32/AArch64 builds
under QEMU. Three isolated mutations are rejected, including the previous lost-
retry behavior, lost EXCLUSIVE registration and an uncleared successful timer.
Working source is unchanged by mutation tests. Hardware execution is separate.
The full offline `make check` gate passes, including MIPS/AArch64 builds with
Hysteria disabled/enabled and the architecture-specific crypto execution gates.

Source review of the suggested Rust client is in `docs/UNBIHEX.md`; it is not a
new protocol reference or a matched performance comparison. Private raw checks
and source identities are retained under
`artifacts/lite-client/listener-recovery-20261030`.

### Controlled Go/C response-close oracle - 2026-10-30

`make HYSTERIA=0 check-spider-close` compares three controlled interleavings
against the real pinned Go 1.27.1 HTTP/2 transport, without vendor overlays.
The reference enters through `vendor/x-net/http2/transport_common.go::NewClientConn`
and `transport_wrap.go::newUserClientConn`; active behavior comes from Go's
`net/http/internal/http2/transport.go::transportResponseBody.Close`,
`clientStream.cleanupWriteRequest` and `clientConnReadLoop.processData/endStream`.
Test-only channels and synctest settle its actual goroutines without sleeps.
C uses the production feed/Do/request/take/write-completion drivers.

For an unread 302 response with Content-Length 5000, both implementations send
no CANCEL when END_STREAM and cleanup finish before Close, one CANCEL when
Close/cleanup precede DATA, and one retained CANCEL when END_STREAM arrives
during the already-selected reset Write. Every case returns exactly one
5000-byte connection-only refund, without a stream refund or PING. Close waits
for actual credit/reset completion and cleanup before redirect continuation.
Independent refund/reset writer ordering is not an acceptance criterion.

The paired gate and entire host cleanup suite pass. The Go oracle passes 100
iterations of all three cases with the race detector. The cleanup suite passes
ASan/UBSan with leak checking; diagnostic builds retain conversion/sign-conversion
warnings instead of treating them as errors, because instrumentation triggers
warnings in unchanged fpt.c/x509go.c. Ordinary builds retain the full -Werror gate.
Statically linked MIPS32 and AArch64 versions of the new C cases match the same
Go oracle under QEMU. Three isolated runtime mutations (wrong reset code,
premature donec and omitted late-body credit) fail the new fixture. Six malformed
candidate logs are rejected; working source remains unchanged by mutation tests.

This increment changes tests and their optional Makefile gate, not the client
runtime. The forced orders establish close semantics for those cases; they do
not measure ordinary CANCEL rates or explain the bigbody distribution gap.
No G2 threshold, scheduler delay, wire behavior or native acceptance is changed.
See `tools/spiderclose/README.md` for execution and scope. Exact source hashes,
build/failed-attempt logs and results are retained privately under
`artifacts/lite-client/bigbody-close-20261030`.

### Host checkpoint v3 provenance and current-runtime comparison — 2026-10-30

The previous host analyzer did not check client executable/stop receipts or the
stand's executed identities and stop results. Its input contract named
server-public.json and omitted the leaf private key and imported network analyzer.
Host v3 explicitly hashes server.json used by the new stand and requires those
inputs, a receipt for each of 24 client phases, and the server/destination receipt.
It also requires frozen criteria, G2Closed false and all 24 completed phases.
Client liveness, binary hash, probe status, SIGTERM and ordinary exit must agree;
server/destination identities, liveness and ordinary exits must agree too.

Host v1/v2 evidence uses its retained analyzer; it is not automatically upgraded.
Native v2 and the separate reference-versus-itself calibration keep their formats.
The comparison calculation is unchanged: 72 rate/timing boundary combinations
match the retained v2 implementation exactly. All 65 analyzer tests pass. Three
isolated mutations disabling client checks, stand checks or input hashing fail
assertions. Nine corruptions of a separate copy of actual evidence are rejected,
with restored controls passing and original evidence unchanged.

A single newly frozen host run compares the current ordinary C runtime with
freshly built ordinary full Xray from the pinned vendor, without trace overlays.
All workloads and live journals stay on container-local storage; export follows
cleanup. Three counterbalanced rounds cover 120 complete captures. All 24 client
receipts and both stand identities/exits validate; driver and cleanup exit 0.
The live plan hash matches the exported plan. The unchanged criteria give:

| Scenario | C/Go CANCEL, of 15 | C/Go selected /h paths, of 15 | C/Go first HEADERS median, us | Criteria |
| --- | --- | --- | --- | --- |
| bigbody | 9 / 3 | 0 / 0 | 278 / 331 | fail: 40-point CANCEL gap |
| gzbody | 0 / 0 | 0 / 0 | 346 / 378 | pass |
| latebig | 15 / 15 | 0 / 0 | 314 / 414 | pass |
| closeafter | 0 / 0 | 10 / 11 | 270 / 358 | pass |

Candidate first-HEADERS regression is zero in every scenario. The selected-path
gap in this run is 6.667 points; the remaining local criterion failure is
bigbody cancellation. This host result does not identify that gap's cause,
estimate any individual fix's effect or replace native/frozen-experiment results.
No C scheduling delay, wire change or threshold adjustment is made. Both
checkpoint_criteria_met and G2Closed remain false. Runtime C source is unchanged
in this increment; the change strengthens evidence validation. Build provenance,
frozen inputs, raw journals and corruption results are retained privately under
`artifacts/lite-client/current-checkpoint-20261030`.

### Scalar REALITY path selection — 2026-10-30

The pinned `vendor/Xray-core/transport/internet/reality/reality.go::getPathLocked`
returns at its chosen iterator position. `src/reality/paths.c::draw` previously
allocated an N-index array and completed the entire map walk before reading one
index. It now calls `lc_gomap_at`: the same hash-derived layout and offsets,
skipping preceding tables by their live counts and scanning the selected table
only to that rank. Live counts use the spent growth budget; these reconstructed
maps have no deletions. Rank bounds and successful entropy draws are unchanged,
including the excluded final rank and eligible root. No fallback is added.
One allocation requesting `N * sizeof(unsigned)` bytes disappears from each
multi-path draw; layout allocations and the returned path copy still exist.
This internal workspace/CPU optimization is marked O9 in DIVERGENCES.md.

The expanded exact-Go fixture passes 206 assertions on host and native MIPS.
All ranks are checked through 21 keys; larger maps through 3600 keys check six
positions per controlled iterator offset, including the final rank. Hinted maps
also compare selection with the full walk through empty/aliased tables. Every
layout allocation is failed in turn, requiring error propagation, unchanged
output and complete cleanup. The static-musl wrappers count caller-level
requests, excluding nested allocator calls. Host ASan/UBSan passes; mutations
of rank, table live count and cleanup all exit 1 on assertions. Restored control
passes again. The native fixture's executed hash is
`d0a86f283fc2f91c1a08986d5d4f70d418851b2c4d93328dd9ddcbcaa65d5a07`.
The initial native fault counter double-counted nested allocator calls; that
test instrumentation was corrected before the retained paired comparison.
Its failed diagnostics remain in the first device archive.

The final full offline `make check` exits 0, including MIPS/AArch64 builds with
both Hysteria configurations and AArch64/x86 crypto execution checks. The optional
Makefile benchmark target builds and preserves the deterministic transcript too.

`bench-spider-choice` runs actual public path draws with deterministic entropy
and checksums, plus full header-map walks. A fixed seven-round 4A comparison
alternates before/after order. All 112 case transcripts and 15 executed-process
receipts validate; each paired checksum agrees. The table gives median process
CPU microseconds per operation, before/after this change, on that device:

| Case | Before, us | After, us |
| --- | ---: | ---: |
| Path, 2 keys | 9.451 | 5.883 |
| Path, 8 keys | 9.489 | 5.996 |
| Path, 21 keys | 24.971 | 23.979 |
| Path, 128 keys | 148.547 | 145.030 |
| Path, 1024 keys | 655.814 | 536.309 |
| Headers, 3 keys | 0.499 | 0.500 |
| Headers, 14 keys | 11.480 | 11.490 |
| Headers, 21 keys | 18.999 | 18.996 |

The small CPU intervals are quantized; tiny differences do not establish gains
or regressions. This is a matched C-before/C-after microbenchmark, not VPN
throughput, a C-versus-Go speed comparison or G2 acceptance. The full header
traversal remains unchanged. A preliminary generic-range variant was discarded
before hardware testing. An initial out-of-line construction variant regressed
the native header microbenchmark; that comparison is retained separately.
Explicit construction/cleanup inlining preserves the
original single-caller optimization after adding a second entry point.

With matched production compiler flags, GNU size reports the MIPS gomap object's
text total growing from 4104 to 6352 bytes. This code-size cost is distinct from
the removed per-draw buffer; it is not a package-size or resident-memory figure.

The controller verifies unchanged boot/configuration hashes and AWG interfaces,
including the earlier attempt, and checks every launched binary via /proc.
Both device archives are checksum-verified before temporary files are removed.
Installed clients and services are unchanged. Private evidence is under
`artifacts/lite-client/spider-pick-20261030`.

### Inherited SIGTERM state and listener release — 2026-10-30

The real daemon previously retained SIG_IGN and a blocked SIGTERM mask across
exec. Six of eight controlled launches could not stop on TERM and kept their
listener bound; the two ordinary launches passed. The initial run exits 1 with
18 failed assertions. `lc-tunnel::main` now restores SIG_DFL and unblocks SIGTERM
before sockets/forks, failing startup explicitly if either operation fails.
Workers inherit usable TERM handling for PR_SET_PDEATHSIG as well.

The pinned Xray entry point, `vendor/Xray-core/main/run.go::executeRun`, explicitly
registers SIGTERM with `signal.Notify`. This correction concerns process lifetime
within O1, preserves C's existing signal exit, and changes no wire behavior.

`build/test-seam --stop-signals` runs the actual daemon with one/two workers under
normal, ignored, blocked and ignored-plus-blocked TERM inheritance. It waits for
every worker's listening log, sends TERM only to the daemon PID, then checks its
signal exit, reaps all adopted workers and binds the same port without REUSEPORT.
The controller restores its original subreaper setting. All 57 assertions pass;
the regular `make check` seam suite includes them. Isolated mutations removing
either disposition reset or mask unblocking both exit 1 on assertions; restored
source passes again.

The full offline `make check` exits 0, including MIPS/AArch64 builds with both
Hysteria configurations and AArch64/x86 crypto execution checks.

All 57 checks also pass on the test 4A using the real MIPS daemon (SHA256
`46fb7e22c0aeb8750d195d84f3adcea7fa1ebb1e90a364bc4ca1058856e0174b`).
The fixture's executed `/proc/PID/exe` hash is verified as
`25a4c8096481ffda369439408cab3af520a0f61ad2478c45f7266907013ca742`.
Boot, configuration hashes and AWG interfaces match before/after. The retrieved
device log archive is checksum-verified before removing temporary files; the
matching binaries remain in local evidence. Services and installed clients are
unchanged. These stop checks do not measure throughput or close G2. Private
evidence is under `artifacts/lite-client/termination-signal-20261030`.

### Atomic supervisor wait and independent retry deadlines — 2026-10-30

The initial controlled fixture reproduced two failures in `supervise`: SIGUSR1
delivered before the blocking wait was not forwarded without another signal or
child exit, and a single EAGAIN fork failure left a slot empty while its healthy
sibling kept running. Earlier parent-death checks still passed.

Managed SIGUSR1/SIGUSR2/SIGCHLD signals are now blocked while inspecting state,
and pselect atomically unmasks them while waiting. SIGCHLD only wakes the reaper;
it does not request a counter reset. Each missing slot has its own deadline.
Fork failures and short-lived crashes use the existing five-second procd interval
from `package/files/lite-client.init`; diagnostic signals do not shorten it or
block the other slots. Long-lived worker crashes still restart immediately.
After a last-worker crash, ECHILD can coexist with a pending restart deadline;
failure of every fork still exits explicitly. Children restore the inherited
signal mask and SIGCHLD action before returning to the tunnel.

The expanded fixture has 52 assertions. Its pre-wait gate acknowledges either
real signal delivery or a blocked pending signal before allowing the wait; no
scheduler race is assumed. Real fork timestamps verify the retry interval.
Statistics/counter-reset signals reach the healthy sibling during crash backoff.
Last-worker restart, ordinary parent-death protection and zero-capacity failure
remain covered. Four isolated mutations (unmasking before waiting, dropping the
retry timer, bypassing fork backoff and retaining the parent's mask in a worker)
fail assertions; restored source/control and focused ASan/UBSan pass.
The full offline `make check` exits 0, including both MIPS/AArch64 plane variants
and the AArch64/x86 crypto execution checks.

The fixture cross-builds for MIPS/AArch64. All 52 assertions pass on the test 4A
with exit 0 and the executed `/proc/PID/exe` hash verified:
`52bc886e92c028fbfd9cbb5778fab2a7cb363dd4fb793d43075386fc97e49fad`.
Boot, configuration hashes and AWG interfaces match before/after. The retrieved
device archive is checksum-verified before temporary files are removed. Services
and installed clients are unchanged. These process-lifetime observations do not
measure VPN throughput or close G2. Private evidence is retained under
`artifacts/lite-client/supervisor-wait-20261030`.

### Supervisor parent identity and failed protection — 2026-10-30

`lc-tunnel::supervise` now captures its own PID before forking and requires that
same parent after installing PR_SET_PDEATHSIG. Checking only for parent PID 1
missed a supervisor that died before prctl when a non-init subreaper adopted the
worker. Failure to install the signal was also ignored. Such a failure now logs
its original error and exits the worker with status 1; the supervisor's existing
nonzero-exit handling stops the group.

`test-supervisor`, part of `make check`, includes the real tunnel source. It
retains the actual supervisor and clock code while link-time section collection
discards the unused tunnel entry point. A real fork is paused before the prctl
boundary until the supervisor has died and the kernel has reparented its child
to the test controller, temporarily marked as a subreaper. The second negative
case injects EPERM only for PR_SET_PDEATHSIG. The positive control installs the
real kernel protection and observes SIGTERM when its parent dies. No production
hook, alternate worker path, scheduling delay or protocol change is added.

All 19 assertions pass; the preceding source fails five while the normal parent
death control passes. Both isolated mutations (PID-1-only detection and ignoring
the protection error) fail assertions; restored controls and source hashes pass.
Focused ASan/UBSan passes, and the fixture cross-builds for MIPS/AArch64. Every
test-created process is reaped and the controller restores its subreaper flag.
The final full offline `make check` exits 0, including the new supervisor fixture,
both architectures with/without Hysteria and AArch64/x86 crypto execution checks.

The exact MIPS fixture passes all 19 assertions on the test 4A with exit 0 and its
executed `/proc/PID/exe` hash verified:
`12341a0894392a8aec74f6e982aaf33ba0a104a0f5f13d6a44a94ecf41c88cc0`.
Boot, configuration hashes and AWG interfaces match before/after. The device
archive is checksum-verified before removing temporary files; installed services
and clients are unchanged. This short process-lifetime check establishes no
throughput, peak-resource or G2 result. Private evidence is retained under
`artifacts/lite-client/supervisor-guard-20261030`.

### Shared spider cache is a REALITY startup requirement — 2026-10-30

The reference's `UClient` retains paths in one package-wide `maps.maps`, protected
by `maps.Lock()` (`vendor/Xray-core/transport/internet/reality/reality.go`).
REALITY's C worker processes therefore require the common arena before serving.
Previously a failed shared-cache initialization logged a warning and continued
with process-local caches. Startup now returns status 1 with the original error
before binding a listener or forking. Hysteria startup does not allocate an
unused REALITY cache.

The real-binary seam fixture uses RLIMIT_AS=128 MiB to make the shared arena's
actual mmap fail, without replacing libc or production functions. Two workers
must fail with the cache/ENOMEM diagnostic, on both free and occupied ports.
The occupied-port case verifies that cache validation precedes listener setup.
Controls with one worker under the same limit and two workers without it both
accept a loopback connection. This is a virtual-address limit, not a RAM budget.

All 16 focused assertions pass. The preceding binary fails five of them; both
controls pass. Two isolated mutations (continuing after failure and validating
the cache after the listener) are rejected, and the restored source/control
passes. The seam fixture's elapsed-time variable also uses int64_t so its 64-bit
time_t arithmetic is not narrowed to a 32-bit long on MIPS; the original strict
cross-compile failure is retained. Run just these cases with
`build/test-seam --cache-startup`; the regular `make check` seam suite also executes
them. The final offline gate exits 0, including MIPS/AArch64 with both plane
configurations and AArch64/x86 crypto execution checks.

All 16 startup assertions pass on the test 4A with exit 0 and no resource guard
triggered. The fixture's executed `/proc/PID/exe` hash is verified:
`cd43409a33cf06348cdf31cdf79044e28157f48abe785e1ea8d32573bab83bd0`.
The REALITY tunnel it launches is checksum-verified before and after execution:
`3676731011802f5942b4aef0b222676647272ca0a0ba2216d7448d184e354d41`.
Boot, configuration hashes and AWG interfaces match. Owned test processes and
temporary files are removed after the device archive is checksum-verified;
installed clients and services are unchanged. This startup correction does not
establish VPN throughput, path-selection frequency or G2 acceptance. Private
evidence is retained under `artifacts/lite-client/cache-startup-required-20261030`.

### Shared spider cache owner-death recovery — 2026-10-29

The pinned reference keeps harvested paths under `maps.Lock()` for the process
lifetime (`vendor/Xray-core/transport/internet/reality/reality.go::UClient`,
the `get` closure); `getPathLocked` draws from those same retained keys.
The C multiprocess cache must retain committed membership when one worker dies.
Previously `store_lock` marked EOWNERDEAD consistent without repairing lookup
metadata. Death between publishing a new table and its mask could hide old keys;
death before count publication left an uncommitted lookup slot behind.

The retention fixture reproduces both failures on the preceding source using
real forked owners that exit without unlocking the robust mutex. Recovery now
rebuilds the derived lookup table from committed keys before marking the mutex
consistent. Release stores publish initialized allocations before offsets,
capacity and count, including on MIPS32. Committed keys, stored map hashes and
random draws are unchanged. Other mutex errors return failure; they never permit
access without the lock. No alternate route, root-path substitution or scheduling
delay is added.

All 22 retention assertions and the existing exact Go path-choice oracle pass.
ASan/UBSan passes; three isolated mutations (omitting rebuild, dropping the final
key, accepting lock errors) fail assertions, with source-restored controls passing.
Six new checks cover interrupted insertion, table and array publication, completed
insertion, a second owner dying during recovery and an unrecoverable mutex.
Static MIPS/AArch64 builds pass. QEMU MIPS returns ENOSYS while initializing the
process-shared robust mutex, so it does not validate these cache checks.
The fresh offline `make check` exits 0, including both architectures with/without
Hysteria and the AArch64/x86 crypto execution checks. All 669 source, test, tool,
patch and build-input hashes match the working tree. The preceding full gate's
exit 2 is retained: three misplaced vendor citations in comments were clarified
against the pinned sources, without disabling or weakening the citation gate.

The exact MIPS fixture passes all 22 assertions on the test 4A, OpenWrt 24.10.8,
with exit 0 and the `/proc/PID/exe` hash verified:
`b366a19cc46a34a4c4352019e65eabd75f8e91c1b9d8dea88d59fb17ca44e0fe`.
Boot, configuration hashes and AWG interfaces match before/after; services are
unchanged. This short fixture does not establish peak memory, throughput,
AArch64 hardware execution or G2 acceptance. The device archive is checksum
verified before temporary-file removal. Private evidence, including setup
failures and the unsupported QEMU run, is retained under
`artifacts/lite-client/cache-owner-death-20261029`.

### Ordinary Xray-versus-itself path-rate calibration — 2026-10-29

A frozen host control runs twelve blocks of closeafter, three rounds per block,
five connections per phase: 360 complete captures. Both `ref` and `lc` labels run
the identical ordinary full-Xray executable and JSON configuration. LiteClient
is not a participant. Clients restart for each phase; the five retries share its
cache. Role order is counterbalanced within/across blocks. Stand and journals
stay on container-local storage, with loopback traffic only. The complete plan
and input hashes precede traffic; no block is dropped, pooled for acceptance or
repeated for its result.

The unchanged 10-point selected-path criterion rejects **five of twelve**
comparisons between these identical implementations. Every rejected block differs
by two selected harvested paths out of fifteen, 13.333 points. The ordinary
native C/Xray checkpoint's 10/15 versus 12/15 pattern occurs in this reference-only
control too (blocks 2 and 5).

| Block | Xray A selected /h paths | Xray B selected /h paths | Rate criterion |
| --- | --- | --- | --- |
| 1 | 12/15 | 11/15 | pass |
| 2 | 10/15 | 12/15 | reject |
| 3 | 11/15 | 12/15 | pass |
| 4 | 11/15 | 9/15 | reject |
| 5 | 10/15 | 12/15 | reject |
| 6 | 11/15 | 9/15 | reject |
| 7 | 12/15 | 10/15 | reject |
| 8 | 12/15 | 12/15 | pass |
| 9 | 11/15 | 12/15 | pass |
| 10 | 12/15 | 11/15 | pass |
| 11 | 12/15 | 11/15 | pass |
| 12 | 12/15 | 11/15 | pass |

CANCEL matches in every block and all timing comparisons meet the unchanged
100-us regression limit (largest signed positive difference: 87 us). The five
rejections therefore come from the selected-path check. The reference retains
root as an eligible choice in `reality.go::getPathLocked`; the count of selected
`/h` paths is not a count of successful harvest commits. This control does not
observe each ordinary connection's commit, identify the cause of every root
choice, estimate a population false-rejection rate or establish native acceptance.
It does demonstrate that this rate-check failure alone is not evidence of a
C-specific implementation defect. Earlier checkpoints remain unchanged; G2 stays
open under its existing policy.

`calibrate_paths.py` validates the complete control, executed identities,
wire/probe/progress records and cleanup. `compare_scenario` extracts the existing
comparison unchanged; 72 boundary combinations match the archived comparator
exactly, and the normal four-scenario entry point still uses the same policy.
All 57 tooling tests pass. Six analyzer mutations and six corruptions of an
isolated copy of the real evidence are rejected, with controls restored and
original evidence unchanged. Driver/cleanup exits are 0 and no test processes
remain. Private raw evidence: `artifacts/lite-client/xray-path-calibration-20261029`.

### Exact Go 1.27 path-choice oracle — 2026-10-29

`tools/spiderchoice` adds a pinned Go 1.27.1 oracle beside the existing Go 1.26
statistical fixtures, which continue covering Hysteria. A test-only GOROOT overlay
exports the actual map Hasher/seed and overrides only `Iter.Init`'s starting
offsets. Map insertion, growth, splitting and `Iter.Next` execute unchanged Go
code. Original runtime files are hash-checked before and after generation; a
different toolchain is rejected. No runtime overlay enters a shipped client.

`test-spider-choice`, registered in `make check`, compares 3120 complete iteration
orders across 40 real maps at twenty sizes, 1--3600 keys. The 21-path stand set is
included. For small sets, every slot offset is covered; larger sets include table
growth, splitting, directory aliases and unsigned offset wraparound. Hashes and
expected orders are retained with the generated fixture, rather than inferred
from selected-path frequencies.

The public C path draw and real rejection sampler then match 22272 controlled
rank/offset choices for sets up to 21 keys, with unchanged cached hashes/counts.
Two additional cases require rejecting an unacceptable random word; one requires
failure instead of a root fallback on missing entropy. All 83 assertions pass.
Five isolated mutations fail at assertions: including the final rank, using an
insertion index, ignoring an entry offset, removing rejection, or returning root
on entropy failure. Controls pass before and after restoration.

Host ASan/UBSan, both pinned cross-builds, and QEMU MIPS/aarch64 pass. The same
stripped MIPS fixture passes all 83 assertions on the test 4A with exit 0 and
the executed `/proc/PID/exe` hash verified:
`654acd01b836f15cb3c264b3f486982d7150a4fe3e6158713492b72e27028dbf`.
Boot/configuration/interface comparisons pass. The short hardware fixture yielded
one resource sample, so no peak RSS or continuous minimum-memory claim follows.
Temporary test files are removed after retaining the output.

The full offline `make check` passes, including both router architectures and
Hysteria configurations. Private evidence is
`artifacts/lite-client/spider-choice-20261029`. This found no selection error in
the tested layouts and inputs; runtime code, random choices and G2 criteria are
unchanged. It does not reclassify earlier checkpoints or close G2.

### Native paired cache retention on 4A — 2026-10-29

A separate frozen `native-cache-retention-trace-v1` diagnostic runs the overlaid
C client and pinned Xray protobuf runner on the test 4A (MT7621, OpenWrt 24.10.8).
Both use the same LAN path to a local Docker REALITY/destination stand. Before
device execution, full Xray and the overlaid runner pass a ten-connection host
control against the same destination: five draws and commits each, exact cache
membership and valid opening frames. This is a functional control, not a timing
or distribution comparison.

The completed native run has two counterbalanced rounds, reference/C then
C/reference, five connections per phase: twenty complete captures. Each client
records ten commits in total; every commit and later draw retains `/` plus all
twenty harvested paths, count 21 and membership mask 2097151. Wire path multisets
match the observations in every phase. The reference selects `/` after commit
once in each round, with all 21 members present; C selects harvested paths after
its initial root in both rounds. Neither outcome is required by the analyzer.
This directly verifies retention in the tested native connections without
forcing path selection or treating a legal root draw as loss.

The native analyzer requires explicit `--native`, the native plan/observer schema,
the runner's original source hash, all input/executed binary identities, probe
exits 52/56, liveness and normal termination (shell status 143 for C, 0 for the
reference). Continuous one-second memory samples cover staging, all four phases
and cleanup, with a frozen 4096-KiB floor and 240-second device limit. Minimum
sampled MemAvailable is 4752 KiB; this is not an instantaneous minimum or RSS
peak. The monitor exits 0. Boot identity, configuration hashes and AWG interface
listings compare unchanged; no installed client, service or network setting is
changed. Test private keys stay in the local stand.

The 50-test tooling suite passes. Four isolated native analyzer mutations are
rejected: ignoring monitor exit, memory floor, phase coverage or the frozen
guard. Controls pass before/after, and the shared source is unchanged. The native
generator's default host outputs remain byte-identical to the preceding host
observers. Runtime code and pinned vendor sources are unchanged; the MIPS C
observer is cross-built in the documented build environment, and Go uses an
overlay on the existing runner. Device archive SHA-256 is
`1d1fc970dd8dedad1b2c00274353aa80cf908f8b198e2cd17ea25739da2b9c09`.

Private evidence is `artifacts/lite-client/native-cache-trace-20261029/completed`.
Preparation failures and the preceding three-phase run are retained separately;
that run exhausted the stand's initial 300-second preparation/workload watchdog.
The completed fresh run uses a 600-second stand watchdog and the same 240-second
device guard, executable bytes and diagnostic criteria. No partial observations
are pooled, and no repeat is selected for its random path choices.

This is native cache-retention evidence, not timing, selection-frequency or G2
acceptance. The earlier ordinary native v2 checkpoint remains failed under its
unchanged selected-path rate criterion; this run does not reclassify its root
choices or close G2.

### Paired closeafter cache trace — 2026-10-29

The test-only generator `tools/vendorcap/nativeclient/prepare_cache_trace.py`
observes `src/reality/paths.c::lc_spider_path/lc_spider_sink_commit` and pinned
Xray `transport/internet/reality/reality.go::UClient`. The reference draws
firstURL from its package-level map and harvests after successful `io.ReadAll`;
`getPathLocked` still permits the retained root. The observers add no random
draws or protocol decisions. They retain bounded in-memory snapshots under the
existing cache mutex and dump only after traffic. C uses its existing SIGUSR1
statistics path; the reference dumps during normal shutdown.

A frozen host-only closeafter diagnostic ran two rounds of five connections per
client, reference/C then C/reference: twenty complete captures in total. Every
phase has five draws and five commits. Every commit and subsequent draw retains
all 21 expected paths (`/` and `/h0`--`/h19`), membership mask 2097151. The second
C phase selects `/`, `/h18`, `/h5`, `/h1`, `/`: its final root draw follows four
successful commits and still observes all 21 paths. Thus that root selection in
this run is not cache loss. Trace and wire path multisets match per phase;
individual cache events are not assigned to sockets or forced into capture order.

`analyze_cache.py` validates the frozen plan, complete dumps, exact membership,
wire opening/path invariants, original/generated source hashes, executed binary
hashes, process liveness and curl exits 52/56. All four phases and stand cleanup
finish successfully; C retains normal SIGTERM exit -15 and Xray exits 0. The
analyzer regression suite passes 45 tests, including missing/lost commits,
membership corruption, changed wire paths, incomplete dumps, input changes and
invalid process receipts.

Four isolated analyzer mutations are rejected with exit 1: disabling commit
membership, wire-path matching, original-source identity or probe-exit checks.
The initial membership mutation survived because the next draw also detected
the corrupted cache; adding corruption of the final commit closes that coverage
gap. Controls pass before and after mutation, and shared sources remain intact.
The full offline `make check` exits 0, including both Hysteria configurations for
MIPS and aarch64, ARM64 PMULL/NEON execution and five x86 CPU profiles under QEMU.
This cross-build/emulator coverage is separate from native protocol acceptance.

Production runtime sources and the pinned vendor tree are unchanged by this
instrumentation; C builds use restored isolated copies and Go uses overlays.
Private evidence, including the driver, plan, binaries, overlays and raw logs, is
under `artifacts/lite-client/cache-trace-20261029/run-v2`. The earlier partial
attempt is retained separately: its listener readiness check missed IPv6 listeners;
the completed driver checks both `/proc/net/tcp` and `/proc/net/tcp6`. No partial
captures are pooled into the completed result.

This establishes direct host cache retention in the observed connections, not
timing, selection-frequency or native acceptance. It does not explain the earlier
native v2 checkpoint's individual root choices or change its failed result.
G2 remains open and its acceptance thresholds are unchanged.

### Direct spider-cache retention fixture — 2026-10-29

`test/spiderpaths/test_retention.c`, registered as `test-spider-retention` in
`make check`, observes exact membership and retained per-key hashes under the
real `paths.c` store lock. The implementation is included only in the test
translation unit; no production observer API, wire behavior or scheduling changes
were introduced. The pinned reference is Xray's `reality.go::UClient`, whose
package-level map is populated after successful `io.ReadAll` and retained for
later connections (lines 198-257).

All 16 assertions pass on x86-64 and with ASan/UBSan. They cover discarding an
uncommitted body, twenty harvested links beside the retained root, duplicate
commits, moving an already-populated cache to shared memory, producer exit,
visibility to a later worker, idempotent sharing, and four concurrent producers
adding eighty distinct links twice across table-growth boundaries. The final
cache holds exactly 102 keys; every original hash and every new key is checked
directly, without using random draws as a membership test.

Two isolated mutations fail with exit 1 at the intended assertions: replacing
MAP_SHARED with MAP_PRIVATE loses the producer's commit in the parent; suppressing
the commit insertion loses the twenty harvested links. The source manifest is
unchanged after restoring the isolated copy. The shared checkout is never mutated.

The same fixture cross-compiles statically with both pinned OpenWrt toolchains
(MIPS little-endian and aarch64). QEMU-user 10.0.13 cannot complete shared-cache
initialization: its `get_robust_list` returns ENOSYS (errno 89 on MIPS, 38 on
aarch64). These are failed emulator runs, not passing target execution. The
identical stripped MIPS binary passes all 16 assertions on the test 4A with
exit 0; its SHA-256 is
`580c9ae74cee7746fd259b1e358e2c3907a86201f85313f3fe39ff03b023e882`.
Boot identity and AWG interface listings compare unchanged. MemAvailable samples
before/after the successful fixture are 22664/22524 KiB; these are not peak or
minimum-memory measurements. No installed client or network service is changed.

The initial device fixture failed with ENOMEM under a 384-MiB virtual-space
limit: migrating a populated cache briefly holds both the private and shared
256-MiB MAP_NORESERVE mappings. A 768-MiB virtual limit admits that migration;
it does not allocate those mappings as resident RAM. The successful device run
uses that corrected test limit. No production memory limit was changed.

The build environment follows `docker/Dockerfile`, with Debian packages fetched
from the Yandex mirror and both pinned Go archives fetched from the Aliyun
mirror. The Dockerfile's Go versions and SHA-256 checks are unchanged. Build
receipts, source hashes, mutation logs, QEMU failures and device results are
retained outside Git.

This is a local cache-lifetime/ownership fixture, not a paired C/Go connection
trace. It does not explain a particular closeafter root selection, replace the
ordinary checkpoint or frozen experiment, measure performance, or close G2.

### Owner decision: preserve faster C execution — 2026-10-28

The owner confirmed that speed/stability improvements are allowed while protocol
behavior must remain unchanged. Matching Go scheduler timing or the frequency of
its legal interleavings is not the objective. No artificial delay, forced cleanup
priority or TLS-owner transfer is introduced to imitate those timings.

Checkpoint v2 therefore measures first-request regression as
`max(0, median_C - median_Go)`, with the same 100-us budget. It reports the signed
delta and absolute difference separately. Earlier C HEADERS are allowed; C
100 us later still passes, and 101 us later fails. The 10-point cancellation/
harvesting checks, wire validation, input/executable identity, counterbalance,
resource guards and restoration checks remain intact. This is an explicit
acceptance-policy revision, not a protocol change or a new measurement of old data.

New plans use host-g2-checkpoint-v2/native-g2-checkpoint-v2 and the explicit
timing_regression_us criterion; native plans mark criteria_frozen. Legacy schemas
or absolute-gap criterion fields are rejected, with no compatibility alias.
Retained v1 plans, hashed analyzers and absolute-gap failures stay unchanged and
are replayed using their archived sources. The frozen full experiment is not
overwritten, pooled or retroactively marked successful.

### Fresh native v2 checkpoint — 2026-10-28

A fresh 120-connection ordinary 4A run uses the approved v2 policy, with the
same C/reference executable bytes and three counterbalanced rounds of all four
scenarios. The frozen helper sources match the current sources. Wire validation
is byte-identical to v1; no protocol implementation or scheduler delay changed.

| Scenario | C/Go CANCEL | C/Go selected harvested paths | C/Go first HEADERS median, us |
| --- | --- | --- | --- |
| bigbody | 15/15 / 15/15 | 0/15 / 0/15 | 2044 / 6078 |
| gzbody | 0/15 / 0/15 | 0/15 / 0/15 | 2183 / 5624 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 2106 / 5645 |
| closeafter | 0/15 / 0/15 | 10/15 / 12/15 | 2055 / 5501 |

Candidate latency regression is zero in all four cases. Bigbody, gzbody and
latebig meet checkpoint criteria. Closeafter does not: the retained selected-path
rate check differs by 13.3 points, above 10. checkpoint_criteria_met and G2Closed
remain false; this run is not relabeled or repeated until it happens to pass.

The metric named harvested counts requests selecting /h0--/h19, not successful
cache commits. Root / remains an eligible random choice after harvest in
`vendor/Xray-core/transport/internet/reality/reality.go::getPathLocked` and
`src/reality/paths.c::draw`; it is not deleted when links are inserted. One C
round requests /, /h0, /h0, /, /h18: cache reuse is demonstrated before that
later root choice. Another starts /, /, /h5, /h6, /h1, which alone cannot
distinguish a root draw from delayed harvest. No cache-loss conclusion follows
from the two extra root requests. This remaining check needs direct commit/
retention evidence rather than forcing a harvested path or weakening the
threshold. Historical measurements and the frozen full experiment stay separate.

All 24 launched executable identities, wire captures, acknowledged phases,
process identities, probe exits and memory coverage validate. Minimum available
memory is 7728 KiB; device, monitor, restoration and stand-cleanup exits are zero.
Boot/configuration hashes are unchanged; AWG/client/cron remain off on 4A. No
AX3000T or remote server changed. Six isolated evidence corruptions are
rejected with restored control passing and original evidence unchanged. Tests
include earlier C acceptance, +100/+101-us regression boundaries, legacy-schema
rejection and a legal root request after a harvested path. The runtime binaries,
raw journals, frozen v2 plan, owner decision and validator identity proof are
retained outside Git.

### Cleanup-to-Do handoff trace on 4A — 2026-10-28

A separate instrumented diagnostic covers two counterbalanced bigbody pairs
(20 connections, 10/client) on the same test 4A and local-journal stand. It
adds bounded in-memory C markers for Do notification, wait-predicate return,
step entry and next-request queueing. Trace output is dumped after each probe;
there is no synchronous per-event logging or new scheduler wait. Ordinary
main.c/fetch.c remain byte-for-byte unchanged from the preceding checkpoint.
The instrumented binaries have SHA-256 C
`d708b495b51a146fbf8aef6d6b4c9ff9e7a2d3a0649c2e2d295eb51938ca3ed3`
and reference
`3ac47dd8b6d142899105e6704260361301813c897c9b55e155cd0cd595d9b19e`.

The active pinned Go 1.27.1 reference is
`GOROOT/src/net/http/internal/http2/transport.go::cleanupWriteRequest`,
`transportResponseBody.Close` and `clientConnReadLoop.processData`. Its transport
is exposed by the x/net wrapper; the legacy vendor/x-net/http2/transport.go is
excluded by its go1.27/!http2legacy build tag. The active original Go transport
and net/http files compare identical to the retained originals. Generated Go
trace overlays and runner compare identical to the source receipts of the
reused traced reference executable. Cleanup closes donec after stream removal
and the final writer-error check, matching the C contract under inspection.

All ten C first-DATA handling events occur after successful reset completion
but before stream removal and donec. All ten redirected request queues follow
donec and precede their HEADERS markers. Four connections observe a Do wait
return after donec; six proceed without that additional wait-return marker.
Thus the observed early-DATA window precedes Do's donec handoff and cannot be
explained by later Do wake/redirect preparation. It narrows the next inspection
to TLS-Write completion and resumption of request/cleanup; it does not prove a
particular OS scheduling cause or justify running cleanup on the TLS owner's
stack. Reference DATA follows redirected HEADERS in nine connections; in the
tenth the peer completes early and no reset is selected. Multiple DATA fragments
and that no-reset case are valid and are checked without requiring one DATA
event or inventing a reset. Credit accounting and cleanup milestones agree
with all 20 wire captures.

Device, monitor, restoration and stand-cleanup exits are zero. All four launched
binary identities match the frozen inputs. Minimum MemAvailable is 7972 KiB;
boot/configuration checks pass, and AWG/client/cron remain off. No AX3000T or
remote server changed. Instrumentation can perturb interleaving and is not
performance, statistical equivalence or G2 acceptance evidence. The preceding
ordinary 120-connection checkpoint remains separate. All 31 analyzer/plan tests
pass, including fragmented DATA, clean no-reset completion and added handoff
events that leave credit attribution unchanged.

### Counterbalanced native four-scenario checkpoint — 2026-10-28

The same ordinary MIPS C and pinned Xray test-distribution binaries as the
preceding 4A diagnostic now run all four scenarios in three paired rounds:
120 connections, 15 per client/scenario. No protocol source changed between
runs. Native ELF hashes remain C
`e4bd5e56cfd160789af6b6786a7bf780482c34cbccfc123eb9f68ac0699d024e`
and reference
`66f7a607930785689e4c556d803d2453575fc3779260f6db8c49e34bbdee76a6`.
Reference source and adapter receipts also match the current pinned files.

The frozen native-g2-checkpoint-v1 plan is generated and independently
validated before workload startup. Bigbody/latebig first roles are Go/C/Go;
gzbody/closeafter first roles are C/Go/C. The first three scenarios rotate;
closeafter stays last each round. The plan validator checks all 24 role phases
in 12 adjacent pairs, complete coverage, per-scenario role counterbalance,
the unchanged 10-point/100-us criteria and the 4096-KiB/1200-second guards.
There are 24 phases (12 adjacent pairs), not 24 independent experiments.
All journals remain on device tmpfs/container-local storage until cleanup.

| Scenario | C/Go CANCEL | C/Go harvested path | C/Go first HEADERS median, us | Absolute timing gap, us |
| --- | --- | --- | --- | --- |
| bigbody | 15/15 / 15/15 | 0/15 / 0/15 | 2595 / 5971 | 3376 |
| gzbody | 0/15 / 0/15 | 0/15 / 0/15 | 2558 / 6226 | 3668 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 2363 / 5851 | 3488 |
| closeafter | 0/15 / 0/15 | 11/15 / 11/15 | 2439 / 5858 | 3419 |

Cancellation and harvested-path gaps meet the unchanged rate limits in this
checkpoint. All absolute timing gaps exceed 100 us, with C earlier. The timing
is destination io-return-v2 across the shared LAN/server path, not isolated
execution or VPN throughput. Bigbody connection-credit refund precedes
redirected HEADERS in C 15/15 versus Go 0/15. The earlier, separate native
diagnostic observed both orders in both clients; neither sample establishes
statistical equivalence or the cause of the different frequencies. No delay or
forced cleanup priority was introduced. G2Closed and checkpoint_criteria_met
remain false. This checkpoint does not replace the frozen full experiment;
related retries are not independent observations and earlier data are not pooled.

The evidence analyzer exits 0 after verifying 120 captures, opening frames,
paths, 24 acknowledged phases and actual executable hashes, process identities,
probe exits 52/56, complete memory monitoring and restoration. Minimum observed
MemAvailable is 7996 KiB; no guard or forced stop occurs. Device, monitor,
restoration and stand-cleanup exits are zero. Boot ID/configuration hashes are
unchanged; AWG, client and cron remain off on the dedicated 4A. No remote server
or AX3000T changed. Six isolated evidence corruptions are rejected with a
passing restored baseline and unchanged original evidence. All 28 analyzer/plan
tests pass, including fixed-role-order, coverage and weakened-criteria failures.
Raw evidence, plan, source receipts and analysis are retained outside Git.

### Native CANCEL/cleanup diagnostic on 4A — 2026-10-28

Current ordinary C (REALITY-only, one worker) and the unmodified pinned Xray
test distribution run on the same MT7621 4A, OpenWrt 24.10.8. Three paired
rounds cover bigbody and closeafter, five related retry connections per client
and scenario per round: 60 connections overall. The shared LAN/server path has
no configured netem. Client journals stay in device tmpfs; destination/server
journals stay on container-local storage and are exported after cleanup.

| Scenario | C/Go CANCEL | C/Go harvested path | C/Go first HEADERS median, us |
| --- | --- | --- | --- |
| bigbody | 15/15 / 15/15 | 0/15 / 0/15 | 2411 / 5604 |
| closeafter | 0/15 / 0/15 | 12/15 / 12/15 | 2349 / 6057 |

Connection-credit refund precedes redirected HEADERS in 13/15 C bigbody
connections versus 1/15 Go connections. Both orders therefore occur in both
clients. Matching CANCEL counts do not establish matching scheduling
distributions. The separate native diagnostic uses fixed per-scenario role
order (Go first for bigbody, C first for closeafter), despite rotating scenario
order. This is an explicit limitation: it is not counterbalanced acceptance.
Related retries are not independent samples; receiver timing includes the
shared path, and the absolute timing gaps exceed 100 us. G2 remains open.
Do not pool this diagnostic with host checkpoints or replace the frozen full
experiment. A full native checkpoint still needs all scenarios and verified
per-scenario role counterbalance before launch.

The analyzer validates all 60 frame captures, 12 acknowledged phases and actual
executed binary hashes, exact opening SETTINGS/window credit, request paths,
probe exits 52/56, process identities and monitor coverage. Minimum observed
MemAvailable is 10108 KiB, above the 4096-KiB guard. Device, monitor, restoration
and stand-cleanup exits are zero. Boot ID and configuration hashes are unchanged;
AWG, client and cron remain off on this dedicated test router. AX3000T and production
nodes are unchanged. Source main.c SHA-256:
`abcafd2ce687209c735b616585e288cdd9df9db8272bf6c6f03015e706e1ac6b`;
fetch.c: `f9ff81cf42d83e2cf98645534974e468c9c5dc57b107330cbbbc7cd6c49d673a`.
Executed MIPS SHA-256:

- C: `e4bd5e56cfd160789af6b6786a7bf780482c34cbccfc123eb9f68ac0699d024e`
- Xray test distribution: `66f7a607930785689e4c556d803d2453575fc3779260f6db8c49e34bbdee76a6`

Source review checks the active Go 1.27 transport's `cleanupWriteRequest`,
`transportResponseBody.Close`, `clientConnReadLoop.processData` and `streamByID`.
An END_STREAM observed before cleanup's reset decision can suppress CANCEL;
one observed after that decision cannot erase a reset selected before waiting
on the writer. Forgotten/aborted streams return connection credit without
reopening the body. Existing split-driver fixtures cover these boundaries.
The complete cleanup fixture passes natively (7762 ok lines, not independent
tests), including selected-reset preservation, early-END suppression, forgotten
DATA credit and final donec acquisition. Fixture SHA-256:
`0b95f381251b44cff114dda76e3d81f4345fcc66e524525ce5325d8efb2ebbfe`.

Preparing that fixture exposed a build-rule defect: test-fetch-cleanup used
TEST_CFLAGS alone, omitting the target library headers and PIE configuration
used by its linked objects. Its rule now applies CFLAGS before TEST_CFLAGS,
preserving target configuration and the test optimization flags. The original
cross-build failure and passing host/native results are retained. Native fixture
compression uses the real cross-built zlib, not production link stubs. This
changes the test build, not runtime CANCEL selection or protocol scheduling.

The final rule passes focused host cleanup execution with HYSTERIA=0 and
HYSTERIA=1, and the native MIPS fixture described above. Divergence checks and
25 analyzer tests pass. Six isolated evidence corruptions (failed restoration,
probe timeout, wrong executed ELF, changed configuration, missing monitor
coverage and rebooted device) are rejected; restored evidence passes and the
original files remain unchanged. Raw journals, source/build receipts, the
frozen native plan and both failed and passing build logs are retained outside Git.

### G2 startup profile and container-local journals — 2026-10-28

The preceding checkpoint wrote live client journals to a Windows Docker bind
mount. Existing startup profiling began only after spider-session handoff and
therefore missed the refusal log and allocation cost. Diagnostic-only
LC_SPIDER_PROFILE now starts at the invalid-certificate branch and separately
records refusal logging, allocation, state transfer, loop registration, fetch,
worker creation and request-worker entry. Atomic release/acquire publication
protects request entry. Ordinary builds exclude these fields and clock reads.
No protocol scheduling, logging suppression, sleeps or thread-pool change is made.

The pinned reference starts the spider in
`vendor/Xray-core/transport/internet/reality/reality.go::UClient`; its
active Go 1.27 `net/http/internal/http2/transport.go::newClientConn` Flushes opening frames before
starting readLoop, and `internalRoundTrip` starts doRequest. Those boundaries
remain intact. A separate instrumented three-round bigbody profile (15 C
connections) on bind-mounted journals locates refusal logging at
503.648--906.518 us, median 612.833 us. Allocation median is 42.081 us; transfer
0.461 us; loop registration 2.244 us; fetch creation 31.561 us; both pthread
creation calls 167.410 us. These intervals include scheduling and are not a
claim about isolated syscall cost or an instrumented acceptance result.

The full ordinary checkpoint is then repeated with all live files on the
container overlay filesystem (`/run/checkpoint`), exporting evidence only after
workload completion and cleanup. The host output mount is v9fs. It uses the
exact same C, full-Xray and destination executable bytes recorded below,
fingerprint, three rounds, 120 connections, role counterbalance, scenario
rotation, five retries per probe and unchanged 10-point/100-us criteria.

| Scenario | C/Go CANCEL | C/Go harvest | C/Go first HEADERS median, us | Absolute median gap, us |
| --- | --- | --- | --- | --- |
| bigbody | 7/15 / 5/15 | 0/15 / 0/15 | 347 / 472 | 125 |
| gzbody | 0/15 / 1/15 | 0/15 / 0/15 | 429 / 424 | 5 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 421 / 488 | 67 |
| closeafter | 0/15 / 0/15 | 11/15 / 11/15 | 357 / 533 | 176 |

The unchanged strict evidence analyzer exits 0, as do driver, cleanup and
evidence export. Gzbody/latebig meet checkpoint criteria; bigbody fails its
13.3-point CANCEL gap and 125-us absolute timing gap; closeafter fails its
176-us timing gap even though C is earlier. G2Closed and checkpoint_criteria_met
remain false. Do not pool these related retries with earlier data, infer a
source-code speedup from changed stand storage, or close the frozen full
experiment/native acceptance. No router or remote server changed.

A separate 15-connection instrumented control with container-local journals
measures refusal logging at 8.036--28.845 us, median 18.635 us; allocation
median is 39.596 us and both pthread creation calls 127.564 us. This supports
the stand-storage diagnosis, without treating independent-run median subtraction
as exact attribution. All instrumented runs have their own binaries and plans.

The final profiler publishes each immutable 64-bit entry timestamp through a
32-bit ready flag (release/acquire), avoiding __atomic_store_8/__atomic_load_8
link dependencies on MIPS32. The initial diagnostic cross-link failure is
retained separately from the passing final result. Final main.c SHA-256 is
`abcafd2ce687209c735b616585e288cdd9df9db8272bf6c6f03015e706e1ac6b`;
fetch.c is unchanged. With profiling disabled, the rebuilt executable compares
byte-for-byte equal to ordinary C SHA-256
`3722acc86d9f35455207f7e4b56ebad6d03dcd490492049870140d177d2e5d3a`.
Host tunnel fixtures pass with profiling enabled and disabled. The analyzer
suite passes 25 tests; ten isolated checkpoint evidence corruptions are rejected
with the restored baseline passing and the original evidence unchanged. All
three actual launched executable pairs match the frozen plan. Divergence checks
pass (12 marked entries). Final profiling mode cross-builds as ELF32 little-endian
MIPS PIE; this is a build check, not execution on a router. The final profiler
also passes one local-journal paired bigbody smoke round (five connections per
client, five complete C profiles, correct executable hashes, clean driver/cleanup
exits). This smoke round is separate from the ordinary 120-connection checkpoint.

### Ordinary four-scenario G2 host checkpoint — 2026-10-28

Timing qualification from the subsequent startup profile: these live journals
were on a Windows Docker bind mount. Fifteen diagnostic samples locate
503.648--906.518 us (median 612.833 us) inside the synchronous refusal log
write, before spider allocation. Thus the first-request timing below includes
a test-storage bottleneck. Retain its exact raw results, but do not interpret
the median gaps as intrinsic client cost. Cancellation counts also describe
this stand; a new container-local-journal run is recorded separately.

This separate checkpoint uses current uninstrumented C (`HYSTERIA=0`, one
worker), full pinned Xray built with Go 1.27.1, and the rebuilt controlled
destination. Destination race tests pass. Both clients use the same loopback
path and Firefox fingerprint. There are three paired rounds, five related
retry connections per client/scenario/round: 120 connections overall, 15 per
client/scenario. Role order is counterbalanced, the first three scenarios rotate,
and closeafter stays last to prevent harvested paths contaminating earlier cases.
These retries are not independent statistical observations.

| Scenario | C/Go CANCEL | C/Go harvest | C/Go first HEADERS median, us | Median gap, us |
| --- | --- | --- | --- | --- |
| bigbody | 4/15 / 8/15 | 0/15 / 0/15 | 909 / 446 | 463 |
| gzbody | 0/15 / 0/15 | 0/15 / 0/15 | 964 / 351 | 613 |
| latebig | 15/15 / 15/15 | 0/15 / 0/15 | 844 / 380 | 464 |
| closeafter | 0/15 / 0/15 | 11/15 / 12/15 | 928 / 372 | 556 |

The unchanged limits are 10 percentage points for cancellation/harvesting and
100 us for first-request median timing. All four timing comparisons fail;
bigbody cancellation differs by 26.7 points. Closeafter harvesting differs by
6.7 points. Timing uses the destination's io-return-v2 clock, not VPN throughput.
The pre-first-request gap cannot be attributed to later cleanup; its cause needs
a separate startup profile. No historical speedup or regression is inferred.

Candidate source SHA-256: main.c
`5a792d35a117fcda9434cacd513c8c3699b706f5fa8496d8573eb9847eaa6df9`,
fetch.c `f9ff81cf42d83e2cf98645534974e468c9c5dc57b107330cbbbc7cd6c49d673a`.
Executed ELF SHA-256:

- C: `3722acc86d9f35455207f7e4b56ebad6d03dcd490492049870140d177d2e5d3a`
- Full Xray: `cbc15e67405c5658cad7a580a93b370f1f6d3b965377e88e019dd4fc8ea91575`
- Destination: `1fb8260fb3e40706ceb55e236e9526f85d61e66a80c2bce759c093976488ec70`

Actual /proc executable hashes match the frozen plan in all three rounds.
The analyzer requires complete paired coverage, the exact input manifest,
48 phase markers, probe exits 52/56, pinned opening SETTINGS/window credit,
valid paths/stream IDs, all 120 captures, and successful driver/cleanup exits.
Both exits are zero. Its 22 tests pass. Ten isolated evidence mutations are
rejected: failed cleanup, missing progress, probe timeout, changed fingerprint,
missing manifest, missing round, lost counterbalance, wrong SETTINGS, missing
connection and duplicate connection. Restored evidence passes unchanged.
The shared parser matches the frozen source snapshot byte-for-byte.

Raw captures, plan, binaries, logs, hashes and analyzer controls are retained
outside Git. This host checkpoint does not replace the separate frozen
136-block experiment or native acceptance. No router or remote server changed.
G2 remains open; checkpoint_criteria_met and G2Closed are both false.

Dated evidence references identify checkpoint groups. Internal run suffixes
are omitted from public paths; exact private paths remain in the retained evidence.

### Coalesced HTTP/2 frame synchronization — 2026-10-28

`fetch.c::cc_run` previously kept the shared state mutex across every frame
already available in a TLS record. The pinned
`vendor/x-net/http2/transport.go::clientConnReadLoop.processHeaders/processData`
publish response/body events without holding `cc.mu` across the next frame.
Concurrent C mode now releases the mutex after a completed frame, publishes its
notifications, and restores readLoop Write ownership on reacquisition. There is
no sleep, scheduler yield, wait for Do, or mandated HEADERS/credit ordering.
Incomplete frames, pending writer acquisition and unfinished Flushes retain
their existing continuations. Stop/closure are checked before the next frame.

The cleanup fixture supplies redirect HEADERS and 5000-byte DATA in one feed.
A test-only synchronization hook lets a real Do pthread close the empty body
at the intervening unlock. It verifies late-DATA connection refund ownership
and exact credit, then separately exercises stop at the same boundary. Removing
the per-frame release in an isolated copy fails this regression. The adjacent
encrypted socketpair fixture now explicitly parks Do until its foreign PING ACK
really encounters EAGAIN: otherwise Do may validly finish before that PING,
which does not exercise the fixture's intended Close-behind-Flush condition.

Host cleanup and focused ASan/UBSan pass. The final cleanup fixture also exits
0 on the test MT7621 4A with OpenWrt 24.10.8, using binary SHA-256
`5b4fb8c6e7c9519b4758829f79b5d9bf8b6c9e260a8a6337ebb59fac8f3df403`.
Boot and configuration hashes are unchanged; AWG, client and cron remain off.
The initial device invocation could not run because `timeout` is absent; the
successful runs use a bounded external watchdog instead. Its one-second memory
sample does not establish peak memory. Device archive SHA-256:
`0370a349a84082c7e72dae4912f164f01ee8522325c3e87aeac4324e78ad4d7d`.
The full offline `make check` gate exits 0 after the socketpair synchronization
correction, including both plane variants on MIPS/AArch64 and the crypto
execution gates. Tested source hashes match the working source for fetch and
both changed fixtures. The first failed gate is retained with its assertion;
it is not counted as a pass.

These are synchronization/lifecycle checks. The paired network follow-up below
does not establish a historical speedup or close G2.

### Paired native follow-up after per-frame unlock — 2026-10-28

The same 4A executes C and the selected pinned Go distribution serially, in four
counterbalanced rounds: bigbody/gzbody, netem zero/20 ms server eth0 egress, five
related retry connections per phase. All 32 phases and 160 native connections
pass the strict diagnostic analyzer. The additional 20 host-control connections
validate full Xray and the selected distribution against the same stand; their
bigbody CANCEL counts are 0/5 and 2/5, illustrating host scheduling variability.
Opening SETTINGS, initial credit, redirect paths and complete frame captures are
checked throughout. The reference binaries are unchanged from the previous
paired diagnostic; new stand credentials and its temporary CA are shared by
both clients in this run and are not production trust material.

| Condition / scenario | CANCEL C / Go | Credit before redirected HEADERS C / Go | Median CPU ticks per five retries C / Go | Maximum reported HWM KiB C / Go |
|---|---|---|---|---|
| local bigbody | 20/20 / 20/20 | 20/20 / 1/20 | 47 / 88.5 | 2688 / 18400 |
| local gzbody | 0/20 / 0/20 | 20/20 / 20/20 | 56 / 117 | 2816 / 19208 |
| egress20 bigbody | 20/20 / 20/20 | 19/20 / 0/20 | 47.5 / 86 | 2688 / 18320 |
| egress20 gzbody | 0/20 / 0/20 | 20/20 / 20/20 | 55 / 115.5 | 2944 / 19364 |

The bigbody ordering difference remains: 39/40 C versus 1/40 Go refunds before
the redirected HEADERS. Allowing a native consumer turn at the frame boundary
does not make its observed scheduling distribution match Go's. There is no
artificial delay or forced handoff. Which refunds originate in Body.Close versus
late-DATA processing has not been established by these wire captures alone.

CPU values are raw process ticks, excluding the first two startup seconds and
including the six-second post-probe interval; tick frequency was not measured.
Four related retry groups per cell are descriptive, not independent statistical
evidence of improvement over an older C build. First-request medians are
2202.5/2234.5 us (C bigbody, delayed/local) versus 5295.5/6289.5 us (Go); their
receiver clock starts after donor TLS completion, so they are not end-to-end
connection latency. No throughput test or G2 acceptance is claimed.

The memory monitor spans staging and every phase: 366 samples, minimum available
9360 KiB, no safety stop or forced client stop. The driver rejects curl deadlines
and local failures, checks monitor liveness between phases, requests a graceful
monitor stop and checks its exit status. Device, restoration and monitor all
exit 0; boot/configuration hashes are unchanged. Only auxiliary services active
before the run are restored; AWG, client and cron stay off. All phase qdiscs report
zero drops. Twelve isolated corruptions are rejected, with original evidence
hashes unchanged and the restored positive control passing.

C binary SHA-256:
`ba4ce9318a939dc465b323adb90166e8a79249eb11dd71335eb8b83187f94b6a`.
Device archive SHA-256, verified after transfer:
`74a2f85530a425182be52e7b6743592377b87e1d89bd3f80e86b6b8352474b0e`.
The temporary stand is stopped, and device files and this run's containers are
removed after retaining the checksummed evidence. Private stand keys are excluded
from the retained archive and from Git. G2 remains open.

### Buffered refund attribution on 4A — 2026-10-28

A subsequent test-only build records refund accounting into a bounded in-memory
ring, dumping after each phase through SIGUSR1. C is instrumented only in the
isolated build copy. Go uses an overlay of Go 1.27.1's actually executed
`net/http/internal/http2/transport.go`, with a test-only dump bridge and runner;
the x/net legacy transport is not the active implementation under that toolchain.
No production/vendor source, node port or fingerprint is changed. The ring,
timestamps, retained connection references and dump bridge affect execution;
these are attribution observations, not timing/CPU/resource comparisons.

Eight phases cover local/20 ms egress, bigbody/gzbody and C/Go: 40 native
connections, plus 20 host-control connections. Both the ordinary evidence
validator and `tools/vendorcap/nativeclient/analyze_refunds.py` pass. All 441
trace events are retained with complete indexed dumps. Connection-local credit
multisets agree with the captured WINDOW_UPDATE values; pointer identities are
not assumed to identify network connections.

| bigbody condition | C unread bytes at redirect Close | C credit source | Go unread bytes at redirect Close | Go credit source |
|---|---|---|---|---|
| local, five connections each | 0 in all five | broken-pipe DATA, 25000 bytes | 0 in four; 5000 in one | late DATA 20000; Close 5000 bytes |
| 20 ms egress, five each | 0 in all five | broken-pipe DATA, 25000 bytes | 0 in all five | late DATA, 25000 bytes |

In this trace, C's earlier refund does not come from closing an already filled
body pipe. Its `process_data` still finds the stream, its pipe rejects DATA,
and the connection credit is accounted in that branch. Go usually takes
`processData`'s branch with no active stream. This narrows the next check to
cleanup/stream visibility relative to reset Flush; these logs do not establish
whether the Go map entry was removed or its read-aborted predicate excluded it.
Neither the accounting events nor this small instrumented run establish why
the uninstrumented scheduling distributions differ.

The corresponding wire still refunds before redirected HEADERS in 10/10 C
versus 1/10 Go bigbody connections; CANCEL is 10/10 versus 9/10. The gzip
control agrees in both conditions: each client returns 102400 bytes from body
reads and 54890 from Close across five connections, with 10978 unread bytes at
each initial Close. No CANCEL occurs in gzip. The before-HEADERS observations
do not imply that independent writers acquire their mutex in trace index order.

Device, restoration and monitor exit 0; 103 memory samples cover staging and
all phases, minimum available 9388 KiB, with no forced stop or safety trigger.
Boot/configuration hashes are unchanged and the original auxiliary services are
restored, leaving AWG/client/cron off. The analyzer suites pass 12 tests; isolated
corruptions of actual trace records are also rejected with evidence unchanged.

Instrumented binary hashes, C then Go MIPS:
`b5d23c47a919d748d0c5442b048e01878332bdaf39510e1f843336d13d8f6206`,
`bac4cc2264d5b2bdc8c1c71ceab035a42a924be663f89b0e8f3b95616954ce22`.
Device archive SHA-256:
`4b411e3d5fceab3b96e0140e57a1b44a2dc524b2d016a6633dca244d0fe070e6`.
The private evidence retains the overlays, instrumentation script, exact compiled
sources and hashes. Temporary trust keys are excluded from its archive and Git.
G2 stays open; no artificial scheduler delay or acceptance change is introduced.

### Cleanup milestones and TLS-owner write service — 2026-10-28

An extended buffered trace adds cleanup entry, reset send/local completion,
post-write continuation, stream removal, done publication and HEADERS submission.
It instruments isolated C and the active Go 1.27.1 internal transport, with the
same host control and eight-phase native design as the preceding attribution
run. All 40 native connections and 880 trace events pass the network, credit
attribution and cleanup validators. In both network conditions, C handles the
first bigbody DATA between reset submission and local Write completion in all
five connections; Go handles it after stream removal in all five. The hypothesized
window after completed Flush but before forget is not observed in this sample.
The gzip controls have no reset and handle DATA before removal on both clients.
No inference about uninstrumented latency or CPU follows from these traces.

`analyze_cleanup.py` checks the producer transitions and reset counts against
the wire. It deliberately permits a Go consumer to observe the closed donec
before the producer records its following `done` marker. Five actual-evidence
corruptions (missing removal, failed/late completion, early redirect and wrong
wire reset count) are rejected with unchanged evidence and restored control.
The analyzer suites pass 15 tests. Device, restoration and monitor exit 0;
103 samples observe minimum available memory 11124 KiB, with unchanged boot and
configuration. Instrumented MIPS C/Go hashes are
`5d76ff0bb2882fae7faf93e3426eb520df5e7a84703d424d249fd145e3b5b0ee` /
`3ac47dd8b6d142899105e6704260361301813c897c9b55e155cd0cd595d9b19e`.
Device archive SHA-256:
`240a01fa8bd220e1aeb74236d0dd45094bf016fd12c65464fa687526e2b72caf`.

The native TLS owner now services already queued Writes before progressing
retained readLoop input. Socket EAGAIN still permits independent read progress;
there is no wait for a producer's continuation or scheduler delay. Terminal read
results drain Writes already queued before that result, including plaintext not
yet taken by TLS. This keeps the existing whole-Write completion/closure contract.
The socketpair regression covers writable output, actual EAGAIN and a real
SETTINGS ACK queued immediately before a terminal read. The read-first mutation
and the candidate dropping that queued ACK both fail the appropriate assertion.

The adjacent foreign-PING fixture now parks both HTTP tasks and waits for an
in-flight task turn to leave before publishing HEADERS/DATA/PING. Parking only Do
allowed the cleanup task to publish donec before PING, which is a valid schedule
but does not test Close behind a pending foreign Flush. Failure output includes
the actual queued bytes, pending/closing flags, done and read readiness.

The final source passes the full offline `make check` gate, focused ASan/UBSan
on the actual included tunnel driver and ordinary libraries, and the socketpair
fixture on the 4A. Both MIPS/AArch64 plane variants and crypto execution gates
pass. The final native fixture (four resource sessions) exits 0, preserves boot
and configuration, and returns session/task ownership to baseline. Its SHA-256 is
`8a0b1eee1518565c91ce6b854ca63020d7f4bd433a2f228b2b2993c71a7d16e6`;
device fixture archive:
`56ed2686d1fe5bd0676867c259297c75b91626c2f5ac3e38893fff5b2f2ffc32`.
Failed intermediate attempts are retained and are not counted as passes.

An uninstrumented follow-up runs the final binary against the unchanged native
Go reference: eight counterbalanced cells, one group of five related retries
each, 40 native connections plus 20 host-control connections. Strict evidence
validation passes, as do twelve isolated corruptions and the restored control.
Bigbody credits still precede redirected HEADERS in 10/10 C versus 1/10 Go
connections; CANCEL is 10/10 versus 9/10. Both gzip conditions agree and have no
CANCEL. This confirms retained frame/lifecycle behavior in the bounded workload;
it does not establish a speedup or close G2. The remaining question is whether
multiple frames processed inside one feed prevent the TLS owner from servicing
an independently queued reset before DATA handling.

The final network run has 95 memory observations, minimum available 6356 KiB,
no safety stop, no forced process stop and zero qdisc drops. Device, restoration
and monitor all exit 0; boot/configuration and auxiliary services are restored,
with AWG/client/cron still off. C binary SHA-256:
`fd36052fb079bf2d3c15b932200b4cd625bff728d04711c6c00ac710e5b36387`.
Final network device archive:
`bd7f17d2aabd7310d0b3896213ba441b031ad80d11b954651772e8e656ce528c`.
The executed main/fixture sources match the final source hashes. Temporary
test containers and device files are removed after retaining the evidence;
private stand keys remain outside Git and are excluded from the archives.

### Feed-boundary handoff to the native TLS owner — 2026-10-28

The split readLoop can now return at a completed frame boundary when a producer
has queued a Write that the sole TLS owner can service. The ClientConn retains
its bufio tail and the fetch retains at most the remainder of one accepted feed.
`read_step` resumes this runnable input; the separate `read_pending` state is not
an invented ClientConn writer wait. Another feed is rejected until retained
dispatch resumes. If a foreign Write is already in flight, parsing is allowed
to continue until the readLoop's actual writer/Flush dependency blocks it.
There is no scheduling sleep or wait for cleanup to finish before input resumes.
Combined-driver callers do not enable this split-mode scheduling state.

The controlled-consumer fixture queues a real reset between coalesced redirect
HEADERS and DATA. With 32/5000-byte bodies it verifies exact bufio/record tails,
no premature DATA accounting, rejection of another feed, exact-once credit,
progress behind an in-flight foreign Write, stop, reset failure and deferred EOF.
EOF is driven through the existing body continuations before closure, rather
than assuming that one consumer call must finish them. Removing the handoff,
accepting a second feed, or failing to resume buffered dispatch each makes the
new assertion fail; the isolated copy is restored byte-for-byte and passes.

Focused ASan/UBSan and the complete offline `make check` gate pass, including
both plane variants for MIPS/AArch64 and the crypto execution gates. The same
cleanup fixture and the actual encrypted tunnel socketpair fixture exit 0 on
the 4A. Their MIPS SHA-256 values are
`a5a2610f0517c1ccbfacd470c358c58aec86ac7c3feb2452dad455117177923b` and
`2144c96dd6dc34008dfe1189dfe8adfb00846de5a17ee2fbd393126a2fbb0ac3`.
The device fixture archive is
`3440f9ee6ba4765add166c0586170d8aa82d1231bbb504d28f76c1523a34c960`.
Configuration and boot remain unchanged. These fixture checks establish the
handoff/ownership contract, not network scheduler equivalence or G2 acceptance.

The ordinary MIPS candidate SHA-256 is
`070e619c4233bdfa2176fcbd11e1084d8ec2e8028a5a0323c08dc0a6f0d978c1`.
A fresh matched 4A diagnostic completes 32 phases / 160 connections: four
counterbalanced groups per client/scenario/path, with related retries within
each group. Both local and server-egress-only 20 ms paths retain the discrepancy:
bigbody connection credit precedes redirected HEADERS in C 40/40 versus Go 0/40;
both cancel all 40 bigbody streams. Gzip has no CANCEL and credit precedes
HEADERS in both clients' 40 connections. These are descriptive observations,
not independent retry samples or a historical causal speedup claim.
All device, restoration and monitor exits are 0; 366 memory samples have a
9664 KiB minimum MemAvailable, with no resource/forced stop. Twelve evidence
mutations are rejected and the original evidence hashes remain unchanged.
The network device archive SHA-256 is
`4f113cf4964e69a967b4073fc49a396a400977b50674e3d6fed7be5704271902`.
G2 remains open. In particular, yielding to service a runnable Write does not
establish Go's ordering between `cleanupWriteRequest`, `forgetStreamID` and
`clientConnReadLoop.processData` in pinned `vendor/x-net/http2/transport.go`.

### Reset completion / stream removal interleavings — 2026-10-28

The retained-feed regression additionally dispatches 32/5000-byte DATA after
reset Flush returns but before request cleanup resumes, and after stream removal
but before the final writer-error check. Together with its in-flight reset case,
these exercise three separate readLoop opportunities in pinned x/net
`cleanupWriteRequest` / `forgetStreamID` / `processData`. The active Go 1.27.1
`net/http/internal/http2/transport.go::clientStream.cleanupWriteRequest` was also
inspected: it likewise removes the stream after reset Flush and before the final
`cc.wmu` acquisition. None of those stages grants readLoop a cleanup barrier.

Each new interleaving checks exact connection credit, active broken-pipe versus
forgotten-stream handling, final cleanup progress and absence of duplicate CANCEL
or credit. A source mutation that blocks retained DATA until cleanup runs and
one that runs cleanup inline on the TLS owner both fail their intended assertion.
The isolated source is restored byte-for-byte and the positive control passes.
Host and ASan/UBSan runs pass, as does the updated cleanup fixture natively on 4A.
The fixture source SHA-256 is
`b66b3eedc210f74d9af00c5ac4ee0e62bc707354d5b2ec2c9674047f2e89bf73`;
its MIPS executable is
`8368c383af31ce602b670fbb1f95e2f5e3f2ad28e45b75cd84f16b231dec16f1`.
The complete native log SHA-256 is
`380c657cf5e8cc9489e2ff4568a5696f4c89b2034a291a03ac5696749405c3d7`.
No services are paused for this fixture; boot identity remains unchanged and
the temporary device files are removed after log verification. AWG stays off.
Only tests/documentation change at this checkpoint: runtime fetch source remains
`c3f8de4a3affb21bc91af34c7af8337076ceefddb79d3237d7776d5b3fa1d8e5`.
No new network distribution or performance result is inferred; G2 remains open.

### Body.Close donec notification ownership — 2026-10-28

Request progress / Write completion now preserve Do's existing final donec wait.
After an empty response body is broken by Close, reset Flush completion wakes
the request executor but neither advances Do's generation nor broadcasts its
condition. Stream removal likewise does not announce donec. The final writer
check sets done and wakes Do once, without new input. Failure and stopped
completion still notify both conditions. A pending Close-credit continuation,
legacy combined mode and terminal events are excluded from the suppression.
Reference: pinned `vendor/x-net/http2/transport.go::transportResponseBody.Close`
waits on donec after its own refund; `clientStream.cleanupWriteRequest` closes
donec after stream removal and its final writer-error check.

The deterministic reset/removal/donec sequence checks notification counts and
generation publication: one Do notification instead of the prior three. It also
checks executor readiness and final Do wait progress, failure and stop. The
fixture source SHA-256 is
`57696fa133f8ffec5f8bc056fab64edbe520d64e671ea1f6974e29fba98e694e`;
runtime fetch source is
`829ee7eeff781ddb0e83e42f18fd7883c9fbc06f2daf99b8f65e3b05f76b8729`.
The updated cleanup fixture passes normally, with ASan/UBSan, and natively on 4A;
the real encrypted tunnel/socketpair suite also passes on the host. The native
MIPS fixture SHA-256 is
`d7166838c346b0ce31529b84c2066c8563f430b6f3305341d246038e598cd251`,
and its complete log SHA-256 is
`0080d7337dca73593f4a3f8e19daf7e28a5053f575748d593af71589cffc2dcf`.
Boot identity stays unchanged; no services are paused, AWG stays off, and the
temporary device files are removed after log verification. These are fixture
results, not a fresh network comparison, G2 acceptance or a VPN speed claim.
The complete offline `make check` gate exits 0, including both plane variants
for MIPS/AArch64 and the QEMU crypto checks. Three isolated mutations restore
unconditional Do wakes, lose the actual donec wake, or lose terminal wakes;
each fails its intended assertion. The original runtime source is restored
byte-for-byte and the positive control exits 0.

### Matched network check after donec wake suppression — 2026-10-28

The ordinary MIPS candidate is
`f5ba70a165ab355de60195d936b721452e07ac6fcf34ee9b448ac69470e2ee21`
(fetch source `829ee7eeff781ddb0e83e42f18fd7883c9fbc06f2daf99b8f65e3b05f76b8729`).
The full-Xray/selected-Go-runner host control passes before device traffic.
The matched 4A run completes 32 phases / 160 connections, with four
counterbalanced retry groups per client/scenario/path. Retries within a group
are related observations, not independent statistical samples.

| Path | Bigbody credit before redirected HEADERS, C / Go | Bigbody CANCEL, C / Go |
|---|---|---|
| Local | 20/20 / 1/20 | 20/20 / 19/20 |
| Server egress +20 ms only | 20/20 / 0/20 | 20/20 / 20/20 |

Gzip has no CANCEL in either client's 40 connections; credit precedes the next
HEADERS in all of them. There is no configured jitter/loss or qdisc drop.
Device, service restoration and monitor exits are all 0, with 365 memory samples
and a 9792 KiB minimum MemAvailable. Twelve corrupted-evidence controls are
rejected and the baseline evidence is restored unchanged. Boot/configuration
checks pass; paused auxiliary services are restored, AWG stays off, and device
test files are removed after archive verification. The device archive SHA-256 is
`5b606b191e5d7b1513ac55edfec4f58ad20743a3c79ea1a35efd87aae21e54ac`.

This diagnostic does not close G2: reducing Do notifications has not eliminated
the credit-order discrepancy. It does not establish a historical causal speedup
or unchanged scheduling frequencies. The older instrumented cleanup trace is
from a different candidate; its DATA timing must not be attributed to this
candidate without a fresh trace. Acceptance criteria remain unchanged.

### Current-candidate cleanup trace — 2026-10-28

A fresh isolated trace overlays the current ordinary fetch source
`829ee7eeff781ddb0e83e42f18fd7883c9fbc06f2daf99b8f65e3b05f76b8729`.
It builds against the active pinned Go 1.27 HTTP/2 implementation and leaves
working runtime/vendor files untouched. Traced MIPS C/Go binaries are
`415a299205be6b2bb349f4768949c4d6043a8ec8af4a0a65b88ed108668e339c` and
`3ac47dd8b6d142899105e6704260361301813c897c9b55e155cd0cd595d9b19e`.
Host controls pass before 8 native 4A phases / 40 connections, one related retry
group per client/scenario/path. This instrumented run is not a performance or
acceptance measurement.

For bigbody, C's first DATA dispatch is between reset-send and reset-complete in
9/10 connections, and before cleanup entry in 1/10. All 10 precede the local
redirected HEADERS marker. Go dispatches DATA after stream removal and that
HEADERS marker in 9/10; its remaining connection has DATA before cleanup/removal
and no reset. Wire CANCEL is C 10/10 versus Go 9/10. Gzip DATA precedes removal
and redirected HEADERS in both clients' 10 connections, with no CANCEL.

The analyzer now distinguishes DATA relative to the local redirected-HEADERS
marker as well as stream removal. Three deterministic cases verify DATA before
and after HEADERS following removal, including Go's consumer running before the
producer's post-donec marker. All 16 analyzer tests pass. Five evidence mutations
(missing removal, failed/late Flush, early redirect, wire-reset mismatch) are
rejected, and the baseline evidence remains unchanged.

`reset_send` is not socket Write entry: in C it precedes queue publication, and
in Go it precedes buffered frame writing/Flush. The observed interval therefore
does not prove socket backpressure or distinguish queued reset work from actual
socket I/O. `headers_send` likewise is a local producer marker, not peer receipt.
The next observation needed for causality is actual TLS-owner Write dispatch;
no forced scheduler wait or protocol-order change follows from this trace.

All device/restoration/monitor exits are 0; 103 samples have a 10592 KiB minimum
MemAvailable. Boot/configuration checks pass, services are restored, AWG stays
off and temporary device files are removed after archive verification. The
device archive SHA-256 is
`a1a98d0c74c9ad433ad71c337e320f76c7bfa09ebbbb9efa5396aa4cdf997f4b`.
G2 remains open; no historical results are pooled with this instrumented sample.

### Ready Write recheck at frame entry — 2026-10-28

The C TLS-owner observer adds reset-take (local Write id / plaintext length)
and conn_write syscall results, preserving errno. Complete cleanup/wire evidence
is validated before dispatch analysis. The baseline trace uses ordinary source
`829ee7eeff781ddb0e83e42f18fd7883c9fbc06f2daf99b8f65e3b05f76b8729`:
all 10 bigbody DATA dispatches occur after reset-send but before TLS-owner take.
All 10 later socket results are successful 35-byte writes; none is EAGAIN.
This identifies queued work rather than blocked socket I/O in that sample.
The extended baseline archive SHA-256 is
`4e4a1767edb1a55983c7bdf067ce3a7c6719f743adaf2c44c5376f0f96fcba86`.

The empty-take / producer-publish / frame-dispatch window is fixed at cc_run's
entry under the protocol mutex. Ready queued output yields accepted input to
the TLS owner before any frame is parsed; in-flight Writes remain independent
of read progress. The previous post-frame check is replaced by this common
entry check, covering retained input and the first frame of a fresh feed.
read_step's return contract explicitly includes this runnable-I/O handoff.
No worker wait, timer, forced cleanup continuation or Write completion is added.

The retained-input race assertion fails on the previous source. Tests cover
32/5000-byte retained and fresh DATA, exact input/credit retention and independent
reads behind an in-flight reset. The Close-decision fixture now takes its actual
refund Write before testing independent peer-END input, preserving its original
decision assertions while distinguishing queued from in-flight I/O.
Focused cleanup/socketpair, ASan/UBSan and complete offline make check pass,
including both plane variants for MIPS/AArch64 and QEMU crypto. The updated
cleanup fixture also exits 0 on 4A. Three isolated mutants remove the entry
check, skip a fresh feed's first frame, or add an in-flight read barrier; each
fails its intended assertion. Restored source passes byte-for-byte.
Runtime/test source SHA-256 values are
`f9ff81cf42d83e2cf98645534974e468c9c5dc57b107330cbbbc7cd6c49d673a` and
`462994eb56553273f88a2b17be18d861232c5fd5af5629c5fdbb68df23780e91`.
The native fixture and complete log are
`aa3e57a0fc93684fc9d8fc06ffcb0f8d7c3eb16418f00a75a14903e01a2fc158` and
`d72608bb2e4e8bea55f41cd14b956de8c9a980fb8e83624cac20849d72b00105`.

A fresh fixed-candidate trace, after the complete gate, uses MIPS C binary
`c23101ddb5a0e3a8422b116f9fb22c4295ed100baf90b121f45a0c47fcaf6fb9`.
The identical traced Go binary is reused only after byte-for-byte comparison of
its compiled transport, HTTP wrapper and runner sources. Host controls pass
before 8 native phases / 40 connections. All 10 C bigbody DATA dispatches now
follow reset completion; nine precede removal and one follows removal. All 10
still precede redirected HEADERS, whereas Go's 10 follow removal and HEADERS.
Wire credit-before-HEADERS is C 10/10 versus Go 0/10. The queued-I/O window is
corrected, but the remaining post-completion ordering discrepancy leaves G2 open.

Nineteen analyzer tests pass. Five cleanup and eight dispatch evidence mutations
are rejected, with original evidence unchanged, for each trace. Dispatch checks
require reset take and socket results, their order, expected reset length and
valid result/error combinations. Each trace has 103 memory samples (minimum
11616 KiB before / 10892 KiB after); device/restoration/monitor exits are all 0.
Boot/configuration and service restoration pass, AWG remains off, and device
test files are removed after archive verification. The fixed device archive is
`398e1c41d85275f69bf12fd30f731f1d3ec89430f57319e7b1c7772d44740cff`.
These are instrumented diagnostics with one related retry group per cell,
not independent frequency estimates, a speed measurement or G2 acceptance.

### Shared task-result publication at the batch boundary — 2026-10-28

Do and request workers no longer release-store intermediate rc=1 results on
each runnable phase. They publish the final batch result before the done flag
and eventfd notification. The TLS owner only tests those result fields for errors;
it does not use rc=1 for task progression. No cleanup phase is merged, no mutex
boundary disappears, and no wait predicate or protocol behavior is changed.

The four-phase task-loop fixture checks that the result remains unpublished
during runnable steps. A test-only write wrapper checks the final result and
error-completion flag at the actual eventfd write, before the notification.
All five task/outcome combinations retain four steps and the original wake
counts: one for errors, two for quiescence plus normal executor retirement.
The preceding source fails on intermediate Do publication. Isolated mutations
restore intermediate Do/request stores or delay publication past notification;
all three fail the intended assertions. Original source is restored exactly and
the positive control passes.

Focused cleanup and encrypted TLS/socketpair tests pass. ASan/UBSan instruments
the changed tunnel/test translation unit against the normal library objects;
the full socket fixture passes with leak detection. The same fixture passes
natively on 4A with four resource-test sessions; all workers join and sessions
are reaped. The native binary is stripped only after compilation. Main/test
source SHA-256 values are
`5a792d35a117fcda9434cacd513c8c3699b706f5fa8496d8573eb9847eaa6df9` and
`3512bce99e4f9ea6fe4e82a8cac176ff0126e7e23ee77885407739a4e1634b8c`.
The native fixture and full log SHA-256 values are
`57aaac31e7dbdd0ed6e85f7bb6588f75923bdd73a134332f9795f2f27677430a` and
`740352979ed1ebbfda459795081e27859f953cd53d6ffdc90fc5116bde56bf61`.
No services are paused for this fixture; boot identity remains unchanged,
AWG stays off and temporary device files are removed after log verification.

This is a status-publication refinement, not a measured VPN speed improvement.
No fresh matched network distribution is claimed for this candidate; the prior
queued-reset and credit-order traces belong to the preceding tunnel source.
G2 remains open under its existing multi-scenario/paired-round criteria.
The complete offline make check gate exits 0, including both plane variants
for MIPS/AArch64 and the QEMU crypto execution gates.

A client that differs from its reference usually does not fail. It connects, carries traffic, and
is identifiable; or it fails one connection in fourteen; or it answers a probe with a FIN where Go
sends seven bytes. Nothing in the client can notice any of that from the inside. So most
tests here compare against something outside this tree: bytes the reference produced, vectors its
own Go code computed, or the reference server and client running next to this one.

There are five levels, from cheapest to most expensive:

1. `make check`, the gate: about 70 unit suites, a set of consistency checks that read numbers out
   of the vendored reference, and builds for both router architectures. Runs offline.
2. Vectors generated by running the reference's Go code, which most of those suites are held to.
3. Cross-builds for mipsel and aarch64, and the arm64 crypto paths executed under qemu. Part of the
   gate.
4. Stands: the reference server (and often the reference client) built from `vendor/`, with this
   client run against it. Run by hand.
5. Measurements on the two routers the project targets, an MT7621 and an AX3000T.

Mutation testing is not a level of its own. It is how each of the above gets checked for whether it
tests anything at all (see [Mutation testing](#mutation-testing)).

## Setting up

The build image, the upstream sources under `vendor/`, the cross toolchains and the link stubs are
all needed before `make check` means anything. [BUILD.md](BUILD.md) has the steps. In short:

```sh
sh tools/vendor/fetch.sh                                # vendor/ at the pinned revisions
docker build -t lc-build:local -f docker/Dockerfile .
docker run --rm -i -v "$(pwd):/w" -w /w lc-build:local make tc-fetch
docker run --rm -i --network none -v "$(pwd):/w" -w /w lc-build:local sh .github/scripts/link-stubs.sh
```

## 1. The gate: `make check`

### Native Hysteria buffered-FIN fix and mixed traffic, 2026-10-28

The earlier executable truncates a 20 MiB HTTP response on the test 4A:
curl receives 16084664 bytes and exits 18 with 4886856 bytes missing. This is
not a transfer-size limit. `hy_copy_down` did not count a previous queued Write
finishing as progress; it could return with the LAN queue empty and QUIC bytes
still buffered. `hy_pump` then closed on FIN alone. It now continues its next
Read after that Write makes progress, and closure explicitly requires an empty
QUIC receive buffer as well as an empty LAN queue. The transport EOF API and
reference windows remain unchanged. This matches quic-go's
`receiveStream.readImpl` final-frame delivery and io.Copy's Write-before-EOF
completion, rather than changing the protocol or adding a size workaround.

The new gate suite `test-hy-tunnel` includes the actual tunnel driver, controls
its QUIC receive interface and uses real nonblocking LAN socket pairs. Four
cases cover FIN already present or arriving later, with writable or initially
blocked LAN sockets. They require queued bytes and the buffered tail to arrive
in order without needing another readiness event, and close only after delivery.
Removing the queued-Write progress accounting in an isolated copy fails the
intended assertion; the restored control passes. The final fixture also passes
on native MIPS. Full offline `make check` passes, including both plane selections
for MIPS/AArch64 and QEMU crypto checks. Its first attempt rejects the new suite's
unrecognised assertion-output format; that attempt is retained before the fix
and successful repeat. Focused ASan/UBSan instruments the fixture and included
tunnel driver with ordinary linked library objects. A whole-program instrumented
build is separately retained as unsuccessful: an unchanged x509go expression
triggers GCC's sign-conversion warning under those flags. No warning suppression
or certificate-code change is used to obtain the focused result.

The device stand builds the full pinned `vendor/hysteria/app` server, revision
`e1366b173ccf5706e1e4630fe8aa654a4b574085`, with Go 1.26.6 and read-only module
inputs. A separate controlled HTTP/UDP target sits behind it. The client verifies
the test certificate pin; upload acknowledgements contain the server's byte count
and SHA-256 only after the server checks every position-dependent payload byte.
Downloads are hashed through FIFOs without storing large bodies in router tmpfs.
After separate 20 MiB download and upload checks, a three-minute mixed loop runs
four TCP transfers plus UDP echo concurrently. Across 91 rounds and preflight /
recovery cases, 370 TCP responses verify 244973568 bytes and 5700 tunnelled UDP
echoes pass byte comparison. A direct UDP control verifies another 60 packets.
Observed UDP payload sizes are 1, 63, 512, 1200, 2048 and 4072 bytes, including
fragmented messages. One deliberately corrupted echoed byte must be rejected.

The 4072-byte boundary includes the test destination's 24-byte Hysteria header:
`UDPMessage.Serialize` and `udpIOImpl.SendMessage` bound the whole message to
4096 bytes before fragmentation. A pinned Go client independently accepts 4072
and silently drops 4073 / 4096 payload bytes; native C matches these expectations.
The initial fixture incorrectly expected a 4096-byte payload to pass. Its failed
result is preserved, as is an earlier file-permission refusal requiring mode
0600 for the temporary password file. Neither behavior is bypassed.

The mixed run stops the disposable server, waits 35 seconds and checks two
failed requests during the outage. After restart, fresh download, upload and
UDP checks pass with the same client PID. A separate lifecycle run waits for
ERR_IDLE_CLOSE after a 45-second outage before checking ordering: twenty more
seconds with no requests produces no connection attempts; the first request
fails in zero seconds with no dial; the second makes one attempt and fails in
five seconds. Restarting the server restores a digest-checked response with
the same client PID, following `reconnectableClientImpl.clientDo`. Its separate
archive is `2f52150b31d6aa48bd718ebe9cb0f430efe6ed149c89092238253166671507ff`.
Boot ID stays unchanged. Across 240 resource
samples over 248 seconds, maximum sampled RSS is 11840 KiB, maximum task count
six and minimum MemAvailable 14752 KiB; no memory safety stop occurs. This is a
bounded functional workload, not a native-reference throughput comparison or a
production memory limit. The independent verifier cross-checks device and origin
counts/digests and rejects nine corrupted evidence variants.

Executed client SHA-256 is
`cdf39d10e03c9df9a2e80bb44b1eb5230f452dd94e6f46b26cb064fa9730fbdd`;
device evidence is
`5fa7e984ea1830d60aba2e276fc8ab3c09bd89d7e8ec5d5ca1b64b2e3164548f`.
Complete and failed-attempt records remain outside Git in the dated Hysteria
authenticated-traffic evidence group. Test processes, device files and owned
Docker resources are removed after local archive verification. AWG, client and cron
remain off on the dedicated test 4A. No remote server, router engine or delivery
asset is changed. REALITY spider G2 acceptance remains open; this single-process
Hysteria workload does not establish multi-process Hysteria traffic performance.

### Native authenticated REALITY traffic and two workers, 2026-10-28

The preceding Hysteria-enabled MIPS executable is run on the test 4A against an
isolated full pinned Xray 26.9.9 server (Go 1.27.1). All 186 current C source
files match the source manifest of that executable. Correct REALITY credentials,
VLESS and `xtls-rprx-vision` carry HTTP responses from a controlled origin. Four
concurrent streams request 64 KiB, 256 KiB, 1 MiB and 4 MiB patterned bodies.
A separate 20 MiB response is hashed through a FIFO, without retaining the body
in the router's tmpfs. Every response must have status 200, the exact byte count
and the independently computed SHA-256 digest.

| Mode | Verified responses | Verified bytes | Resource observations |
| --- | --- | --- | --- |
| One worker, five-minute load loop | 455 | 650575872 | 297 samples over 309 s; maximum sampled RSS 2976 KiB; four kernel tasks |
| Two workers, 20 concurrent-request rounds | 85 | 132644864 | 59 samples over 67 s; maximum summed RSS 6436 KiB; supervisor plus two workers, nine kernel tasks |

Both modes stop the disposable server between completed rounds, require the
next request to fail, then restart that server and verify a fresh response
without restarting the client. The expected failure reports exhausted attempts
in the client log. With two workers, SIGUSR1 and SIGUSR2 to the supervisor also
preserve both worker PIDs; final counters prove that each worker carried data.
Both device commands exit zero. The boot ID is unchanged, the memory safety
guard never fires, and minimum observed MemAvailable is 17516 / 13880 KiB.
RSS sums include shared pages and are not exclusive memory consumption. The
resource observer and retained evidence also consume router resources; these
figures establish neither production limits nor a throughput comparison.

The first attempt exits 22 at the test controller's HTTP 403: Docker translates
the router's source address, invalidating that controller's address check. Its
archive remains separate. A per-run controller token replaces that test-only
check before a complete retry; no client code or protocol behavior changes.
The independent evidence verifier accepts both complete results and rejects six
single-worker and nine two-worker mutations, including digest corruption,
missing responses, resource failure, changed boot/worker identity and absent
worker traffic. Executed client SHA-256 is
`d2587793af1392494278e7a17b95812e25df09f4f6757426e88456a10c4a094a`.
Device evidence archives are
`1e86389a38c5f3e2b168f795aa1afa3d368cc3c8d67a4ebccfa0fd61a4d45497`
and `f01723e27988a44c18eb67dc61eeede0c0709b8aeec07505e443f29cf2ac911c`.
Private scripts, logs, failed-attempt evidence and verification receipts remain
outside Git under the dated authenticated-soak evidence group.

Correct authentication does not enter the camouflage HTTP spider. This bounded
download/reconnect checkpoint does not close G2 spider wire/scheduling acceptance,
test Hysteria traffic, prove upload/UDP behavior or compare with a native Go
client. AWG, client and cron remain off on the test device; no remote server or
router engine is changed. Temporary test processes and files are removed after
the evidence archive hashes are verified locally.

### Native completed-HTTP worker retirement, 2026-10-28

`build/bench-spider-workers 8 250 completed` adds a controlled TLS/socketpair
peer to the existing resource fixture. Actual tunnel workers emit the opening
and request Writes; the peer supplies SETTINGS, an HTTP 200 header block and
a DATA/END_STREAM body. The event loop joins both completed HTTP workers while
retaining their fetch/TLS connection, following pinned Xray's
`reality.go::UClient` connection retention and x/net's `clientStream.doRequest`
cleanup-before-completion boundary. The retained readLoop then authenticates
and answers PING and refunds late DATA's connection credit without restarting
the HTTP tasks. The fixture uses fixed test application keys; TLS/REALITY
negotiation, a live node and internet RTT are outside this workload.

On the test 4A, eight rounds of 1/2/4/8 sessions pass: 32 observations, 120
sessions, 240 HTTP workers retired, 120 authenticated PING ACKs and 120 exact
WINDOW_UPDATE refunds. Each reply is decrypted and byte-checked at the peer.
Kernel task counts return from 3/5/9/17 to the single main task after HTTP
completion, before the retained-connection probes. After closing each batch,
session slots and descriptor counts return to baseline. An additional eight
native observations verify the unchanged blocked-opening mode.

| Sessions | RSS with retained TLS after retirement, KiB | Whole-cycle CPU median, ms |
| --- | --- | --- |
| 1 | 1296–1324 | 11.1 |
| 2 | 1356–1368 | 11.4 |
| 4 | 1432–1452 | 22.3 |
| 8 | 1584–1620 | 45.4 |

Whole-cycle CPU includes the controlled peer's encryption/decryption and
in-cycle observations, not only client work. Phase counters include zero
increments and delayed charging on this target; the reported 1 ns clock
resolution does not provide that accuracy. These numbers cannot be compared
as a speedup/regression against the blocked-opening workload. The largest
recorded stage RSS is 1640 KiB; after batch close RSS is 1272–1284 KiB following
initial allocator/cache growth. Nine external samples observe minimum
MemAvailable 24948 KiB. This short plateau does not prove absence of leaks or
establish production memory, throughput or long-soak acceptance. G2 remains open.

Both host `HYSTERIA` selections and MIPS/AArch64 cross-builds pass; AArch64 is
build coverage only. Focused ASan/UBSan and TSan instrument the included tunnel
code and fetch driver with ordinary remaining modules. The first TSan run
fails the resource assertion because its memory-reclamation thread starts on
the first pthread creation, after baseline capture. The successful run uses
TSan's `force_background_thread=1` to establish that runtime thread before the
baseline, plus per-process ASLR disabling in its disposable test container.
Worker assertions remain unchanged. Sanitizer timings are not device budgets.

Five isolated mutations fail their intended assertions: missing request worker,
leaked wake fd, omitted session reap, omitted HTTP-worker retirement and a
readLoop incorrectly stopped at Do completion. Both unchanged workload controls
pass. The complete host `test-spider-tunnel` also passes, including retained
readLoop backpressure/EOF cases. Source hashes, boot/configuration checks and
device exits match; AWG, client and cron remain paused as requested. No product
protocol change or new full `make check` run is claimed.

Executed MIPS SHA-256:
`0efdfe6eec30e1dc7c883c35f84d1b5cb891974556f3ce5ca47039dee6ba6c47`.
Completed-workload device archive SHA-256:
`566eeb9a1cb962249b7da6bdd07a68ad38a033474f7d8a73a362e9a4c9e623fb`.
Blocked-mode regression archive SHA-256:
`abbb68c274a90614dfbbc0d2708cc64258ce12f42de066f02e8999d8760eccd5`.
Combined private source/build/mutation/sanitizer/device evidence SHA-256:
`60c5a03c676cdc1d67c70599e0c49d8015740f75028d78f15a89c617c4af1217`.

### Native blocked-opening worker budget, 2026-10-28

`make HYSTERIA=0 build/bench-spider-workers` builds an optional resource
observation with ordinary client flags. Its default run performs eight rounds
of 1/2/4/8 sessions, holding each initial HTTP/2 Write uncompleted for 250 ms.
It calls the actual tunnel's `spider_tasks_prepare`, `spider_worker_start` and
`session_close`/`sessions_reap`; no task function is substituted. The hold is a
benchmark observation window, not a delay added to a client or its wire path.
Optional arguments select 1–32 rounds and 1–500 hold milliseconds.

On the test 4A (OpenWrt 24.10.8), all 32 observations pass. Each session adds two
HTTP workers and one eventfd; closing each complete batch returns task and
descriptor counts to baseline. Median observed CPU milliseconds are:

| Sessions | Start | Close | Whole cycle, including observation |
| --- | --- | --- | --- |
| 1 | 2.6 | 1.0 | 3.8 |
| 2 | 3.0 | 1.4 | 4.5 |
| 4 | 4.2 | 2.2 | 6.6 |
| 8 | 6.9 | 4.0 | 11.0 |

Start measures the creation call interval; worker setup can continue afterward
and therefore cross phase boundaries. Hold CPU medians are about 0.08 ms per
250 ms window; the largest observed CPU/wall fraction is below 0.065%.
Short setup phases report zero CPU increments even though the clock reports
1 ns resolution. These are rounded counter observations, not that accuracy or
evidence of zero setup cost. Whole-cycle CPU includes procfs observations;
phase boundaries exclude those observations. Descriptor counts include the
directory used for counting, consistently before and after.

Resident memory reaches 1528 KiB with eight blocked sessions and returns to
1196 KiB after each batch, following the first cycle's growth from 1060 KiB.
Nine external one-second samples observe minimum MemAvailable 26436 KiB.
Neither this short plateau nor the absence of task/fd growth proves a general
absence of leaks. No TLS/network/body work or ordinary completed-task retirement
is measured. This is a blocked-opening creation/stop budget, not production VPN
RAM, throughput, a Go comparison, a long soak or G2 closure.

Host builds with `HYSTERIA=0` and `HYSTERIA=1` pass; MIPS and AArch64 cross-builds pass. AArch64
is build coverage only here. Focused ASan/UBSan instruments the benchmark's
included tunnel code and fetch driver; other linked modules are ordinary
objects. Three isolated mutations (missing request worker, leaked wake fd and
skipped session reap) fail the intended assertions; the unchanged control
passes. Invalid arguments fail explicitly. A bootstrap before HTTP-server
readiness failed before benchmark execution and is retained separately.

Device execution and source/configuration checks exit zero, the original boot
ID remains, and the owner-requested paused AWG/client/cron state is preserved.
No new full `make check` or normal traffic acceptance is claimed.
Executed MIPS SHA-256:
`6b6c34225acd4cd45dfeff8e0f2e4a0c96398ad4e053fe7e76c5f81356b362f1`.
Retrieved device archive SHA-256:
`df9eb73d30093edee49ad1dfe3e20669a510483b04ffa7697facae2ea47fb848`.
Combined private source/build/mutation/sanitizer/device evidence SHA-256:
`84b1b57c64a7da8c2fcec6ff54d03c2ba8ca5d6628fd6b8653c92839a322bc02`.

### Paired native MIPS reference follow-up, 2026-10-28

Both clients now execute on the same test 4A, alternating over the same LAN
stand in three rounds: 15 connections per client per scenario, 120 total.
The reference is a selected-module distribution of pinned Xray, built with
Go 1.27.1; its REALITY, VLESS and HTTP/2 implementations are unchanged.
`tools/vendorcap/nativeclient` records the adapter and build recipe. The host
encoder uses the pinned JSON builder; the device uses its protobuf loader and
`core.New`/`Start`, with the CLI's post-start GC and signal lifetime. This
excludes full-Xray configuration parsing and optional-module startup costs.
Before device execution, full Xray and the distribution each pass 40 host
connections across the same four scenarios. Their bigbody CANCEL counts are
4/10 and 2/10; this structural control does not prove scheduler equivalence.

The first device attempt stops during staging at 4092 KiB MemAvailable. The
completed run follows archival and removal of five inactive old test directories,
which reclaim about 6.4 MiB of tmpfs, and temporary suspension of client, cron,
AWG, DNS, Wi-Fi and LuCI services. The test's SSH path uses wired WAN.
All paused services and all 13 saved configuration/script hashes are restored
after the run; the boot ID matches and AWG HTTPS returns 200. The test driver
and restoration both exit zero. Later, the owner explicitly leaves VPN/control
services paused on this dedicated lab router for continued LiteClient work;
this does not change the recorded restoration result or boot configuration.

Every captured connection has one preface and valid frames. Both clients reach
the expected redirect paths, cancel all 15 latebig streams, send no gzip CANCEL,
and use harvested paths on 12/15 closeafter connections. Bigbody CANCEL is
15/15 for C and 14/15 for the native reference. Per-scenario first-HEADERS medians
are 2.291–2.402 ms for C and 5.319–6.625 ms for the reference, measured at the
destination after its TLS handshake. These are descriptive observations from
three groups of five dependent retries, not independent trials, a throughput
comparison or a general speed guarantee. G2 remains open for the wider case
matrix, worker/CPU costs and longer workload acceptance.

There are 266 one-second memory samples; minimum MemAvailable is 6968 KiB,
including staging. Sampled process RSS peaks are 2956 KiB for C and 19284 KiB
for Go. These exclude exclusive process-tree accounting and can miss short
workers or peaks; both staged executable files also occupy tmpfs.
Six isolated result mutations are rejected; the unchanged analysis passes.

The versioned adapter builds for MIPS, AArch64 and host with verified ELF
targets; its encoder stays host-native during cross-builds. Missing arguments,
missing/invalid protobuf, unsupported modules and a Go version different from
the Dockerfile pin fail explicitly. Encoding reproduces the tested protobuf
bytes and vendor source hashes remain unchanged. The exact final MIPS build
also passes a separate five-connection native smoke and restoration. AArch64
is cross-build coverage here, not execution on the AX3000T. No new full
LiteClient `make check` or installed-client replacement is claimed.

Paired-run C / reference binary SHA-256:
`d2587793af1392494278e7a17b95812e25df09f4f6757426e88456a10c4a094a` /
`614c7ef5c01049306d72b020120cd957d6cb0060fe21249dc9a4b92f9683c9ee`.
Paired device archive SHA-256:
`e92790280ea3a93445bb6f082e23d60b61e68c5a67909b4f6e74c2798ce9f626`.
Final versioned MIPS adapter SHA-256:
`66f7a607930785689e4c556d803d2453575fc3779260f6db8c49e34bbdee76a6`.
Its native smoke archive SHA-256:
`1054952aeb61e76c360c1f0ed502794f458aa0a715b98722720e453e8af049a6`.
Combined private source/control/device/analysis evidence archive SHA-256:
`39298b009a15c184254b461214f924337a6fd456d51b5d4a73206adbc7ccd8f3`.

### Native MIPS spider wire checkpoint, 2026-10-28

The current Hysteria-enabled client was cross-built and executed temporarily on
the test 4A, OpenWrt 24.10.8 / kernel 6.6.144. Three rounds of bigbody, gzbody,
latebig and closeafter produced five retry connections per probe: 15 per
scenario, 60 total. An isolated pinned Xray/destination stand captured complete
HTTP/2 frames. Every connection has one preface and valid frames; redirects
reach stream 3 at the expected path. All 15 latebig connections send CANCEL.
The closeafter runs use harvested paths on 12 connections, following each
fresh process's initial request. Native gzip redirects send no CANCEL.

A complete Xray reference was also cross-built for soft-float MIPS. The first
paired attempt stopped at its first memory sample, MemAvailable 0 KiB, with
both executable files staged in tmpfs. It returned failure and restored the
router. No native reference result or paired performance claim is taken from
that attempt. The subsequent successful run stages only the C executable.
Xray runs the same 60-connection scenario matrix separately on the host as
context. In bigbody, native C sends CANCEL on 15/15 connections and host Go on
3/15; different hardware, scheduling and paths prevent attributing this gap.
This checkpoint does not close G2 or establish a throughput improvement.

The native driver and restoration both exit zero. Across 130 one-second
samples, minimum MemAvailable is 15100 KiB and sampled process RSS reaches
2944 KiB. These observations can miss short-lived workers and do not establish
exclusive process-tree memory, peak thread count or CPU cost. Boot identity and
configuration/script hashes match after restoring client, cron and AWG; all six
client instances run and AWG HTTPS returns 200. No installed client is replaced.

The result analyzer rejects seven isolated mutations: missing connection,
duplicate preface, malformed frame, wrong redirect path, missing latebig CANCEL,
incomplete driver and failed restoration. Its unmodified control passes. The
first analyzer attempt had an incorrect expected latebig path (`/lb`); the
correct expectation `/late` comes from the unchanged destination source.
No product code changes in this checkpoint, and no new full `make check` run
is claimed. Initial build failures from an incomplete offline Go module cache
and missing stand go.sum entries are retained; the documented module preparation
precedes the successful builds.

Executed MIPS client SHA-256:
`d2587793af1392494278e7a17b95812e25df09f4f6757426e88456a10c4a094a`.
Retrieved native device archive SHA-256:
`003bffd38ddd2a9aa296c6bf2a6fe7fd1721d227eb64865e644df7006991f82a`.
Private wire/source/analysis evidence archive SHA-256:
`20238b655e26e21f015c3af894fa196bf9d09c9c9e86242f07eb941a80fd58a4`.

### Hysteria socket-wait failures, 2026-10-27

Two deterministic error-path reproductions fail on the preceding source and pass
after the fix. The send queue's full-socket wait previously ignored negative poll
results other than readiness flags, retrying sendmsg and losing the original
error. The fixture bounds that broken retry with a second EIO; ENOMEM, EINVAL and
EBADF must instead end the first wait with their original errno. EINTR and an
ordinary timeout still retry, while a timeout during stop retains ETIMEDOUT.

The connection loop separately drained the queue's wake pipe before inspecting
a failed poll. The pipe drain overwrote errno with EAGAIN, turning EINTR into a
terminal failure and corrupting the diagnostic for ENOMEM. Real nonblocking-pipe
fixtures verify the original outcome/error and that the wake byte remains pending
after a failed wait. Successful wait processing is unchanged.

These are error-path corrections, following the terminal writer-error handling
in pinned `vendor/quic-go/send_queue.go::Run`. The 150 us sender spin, packet
format, pacing and retry policy are unchanged. No new wire deviation is added.

The full offline `make check` exits zero, including builds with Hysteria enabled
and disabled on MIPS/AArch64 and the existing QEMU crypto checks. The executed
five-file source/fixture/Makefile manifest matches the working source. Focused
ASan/UBSan checks cover the sender wait, real queue lifecycle and connection wait.
The initial host reproductions return nonzero at the intended assertions.

All three fixtures also execute successfully on the test 4A (OpenWrt 24.10.8) and
AX3000T (OpenWrt 25.12.5), with downloaded binary SHA-256 verification, unchanged
boot identity and running client services afterward. The sender fixtures are static;
the connection fixture uses each device's existing libraries. Earlier fixture
cross-build attempts without explicit test header/library paths failed and are
not counted as device validation. Installed clients and configuration were not
replaced. This establishes the failure handling, not a throughput improvement,
a new traffic soak or G2 acceptance.

### Native REALITY traffic and short G2 recheck, 2026-10-26

The existing task-retirement source snapshot was cross-built with Hysteria
enabled for MIPS and run temporarily on the test 4A, OpenWrt 24.10.8. Its
source manifest matches the current tree in all 606 non-document files; the
three changed documents contain subsequent evidence. The native binary SHA-256
is `57ef4db860b02ac563eb4ed477cef760672f76cda47f00706161d092619e3fa3`.

Against an isolated pinned Xray REALITY server on the LAN, 25 rounds of four
concurrent 64 KiB downloads complete successfully. All 100 response hashes
match, the test exits zero, and the boot and AWG interface identities match
before and after. One-second sampling gives 38 samples, minimum MemAvailable
13304 KiB, peak client RSS 2872 KiB and at most four client threads. This is a
short authenticated-traffic check, not a long soak, throughput comparison or
spider wire-acceptance test. The first attempt stopped before starting the
client because available memory fell below the existing 8192 KiB preflight;
a concurrent jq was observed using 8276 KiB RSS. It is not counted as a pass.
The later successful run retains the existing 4096 KiB runtime safety stop.
The native evidence archive SHA-256 is
`1ad1fc47b1030dc658a9027bb118d1c27867e734a7a5f81c6b2cc5cb992f0c64`.

A separate recovery check uses the same binary and test server. A request
succeeds with the expected hash, a request fails while the test Xray is
stopped, and the next request succeeds with the expected hash after Xray is
restarted, without restarting the client. The boot identity is unchanged;
the test exits zero. Thirty one-second samples show minimum MemAvailable
12020 KiB. This checks one server-restart cycle, not WAN recovery, persistent
sessions or a soak. Its evidence archive SHA-256 is
`d3fa29829c873310addda81cecbb8b2261fe9fb84b9aefbcbe0a218fd4523c67`.

An independent longer mixed-workload run is not a pass. Its first launch
stopped at the 8192 KiB preflight, before starting the client. On the next
launch, 36 four-request rounds passed their hashes; during round 37 the
unchanged 4096 KiB runtime guard stopped the client after MemAvailable fell
to 3656 KiB. The four requests in that round failed. Peak sampled client RSS
was 2788 KiB over 53 samples; neither this observation nor a concurrent jq
seen at an earlier preflight proves the full cause of the memory pressure.
After the run MemAvailable was 14356 KiB, the boot identity was unchanged,
and logread showed no OOM-killer entry. The original long-test script names
the short-run memory file in its final summary; the values above are computed
independently from `long-memory.log`. Its failed result and source are retained
with archive SHA-256
`b042c800b0beae8b8f95340f7f1e7fb571251f07d4f55d07b5b1395b4e338bd4`.

The next mixed-workload attempt adds process-name, parent-PID and RSS snapshots
when MemAvailable falls to 10000 KiB; it does not collect process arguments.
It also stops at the 4096 KiB guard: 21 four-request rounds pass, then all four
requests in round 22 fail as the guard terminates the client at 4044 KiB.
Over 31 samples, peak client RSS is 2848 KiB. An earlier snapshot at 9968 KiB
shows the client at 2844 KiB RSS and an nft process at 5116 KiB, with several
shell processes; this snapshot is not at the eventual minimum and RSS values
cannot be summed as exclusive memory. The collection itself has a cost.

A separate 90-sample observation with no LiteClient process reaches 8232 KiB;
its low-memory snapshot includes jq at 7392 KiB RSS. These observations show
background memory pressure but do not establish the exact cause of the guard
events or quantify how much the client contributes. Neither the failed run
nor the passive control is a completed mixed-workload soak. The mixed-run and
control archives have SHA-256 respectively
`04ccb6826c058251b81700c4fbd229fbe8324a1013d3c0f0a3d016c2c7aa3323` and
`b570bace3fe68d1454f2ae1034d96e1c9cd644f240d2b4be79b553e4d821dd2f`.

An additional passive observation on 4A, without LiteClient, correlated the
process ancestry with procd instance IDs. At one observation the diagnostics
instance ran `nft -j list table inet p4vpn`, reaching 5460 KiB RSS; the next
observed diagnostics child was jq, reaching 9204 KiB RSS while MemAvailable
was 4244 KiB. Its arguments matched the policy-consistency filter. A subsequent
full-table nft scan was attributed to the domain-cache instance, followed by
its jq child. The observer itself used processes and memory, so this sequence
identifies concrete sources of pressure, not their exclusive contributions or
the exact cause of either earlier safety stop. Source inspection identifies
`router_runtime_report` -> `router_policy_ready` ->
`domain_policy_consistent`; this does not establish that all earlier
observations followed the same path. The retained observation log SHA-256 is
`c1f1d87c7a7e2a0f8d3678b4c973d2c9423ffdb1ee7dffea5238eb4e822b41bd`.

Two non-deployed experiments compare the policy-consistency check on one
unchanged 4A snapshot (422639-byte nft JSON and 142147-byte policy), while
the test router's client and cron services are paused and restored. Runs alternate
baseline, candidate, candidate, baseline. The device's `/usr/bin/time` is
BusyBox; its reported maximum-RSS field is not reliable as KiB on this device:
a separate sleep process reported 3584 there while `/proc` showed VmHWM 908
KiB. The time-field values below are retained raw, not treated as measured RSS
or evidence of an OOM cause. Follow-up measurements read each jq's `/proc`
status directly.
The streaming experiment returns the same successful result but takes
38.57/38.40 s and raw maximum-RSS fields 25680/25696, versus baseline
15.04/14.97 s and 37888/37888. The tradeoff is not accepted as a production fix.

The second experiment builds address-membership indexes per owned set instead
of retaining indexes for every set at once. It takes 10.98/11.03 s with raw
maximum-RSS fields 37376/37376, versus baseline 15.01/15.07 s and 37888/37376.
It is faster on this snapshot, but these fields do not establish a memory saving.
The test first stopped safely at the 16000 KiB preflight; the repeated run
completed with all four results successful. Both experiments restore the
original services and boot ID and verify the saved configuration hashes. The
two prototypes are not deployed or adopted. Their native evidence archives
have SHA-256 respectively
`5336a93cc0cca4972d887540c91d9fd146e71b893dcbf15b8910b40fba6e6cd5` and
`675aca1f858e96d2b26989fe33e837ef426613a44b661bf5999b40d8345e52e4`.

A third, non-deployed experiment consumes the nft JSON stream one set at a
time, comparing owners while retaining only the aggregate addresses and seen
set names. On another fixed snapshot of the same sizes, alternating baseline,
candidate, candidate, baseline, BusyBox time reports 15.07/15.04 s and raw
maximum-RSS fields 37888/37376 for baseline, 32.22/32.00 s and 17408/17920 for
the candidate. Both candidate runs spend about 99% of their elapsed time on CPU.
The lower reported field comes with a substantial duration and CPU cost, so it
is not adopted. The test lab restores client and cron, confirms the saved config
hashes and original boot ID, and leaves the installed script unchanged. Its
native evidence archive SHA-256 is
`bfd355935202fe1a6fb1de66692462ae55c490759b920bf7f20087894978a529`.

A follow-up reads each jq process's `VmHWM` from `/proc` while comparing the
same three implementations on one fixed snapshot. The first three runs are
not usable for memory: the temporary sampler used `sleep 0.25`, which this
BusyBox rejects, so it recorded only a startup sample. After fixing the sampler
to one-second intervals, the remaining runs report observed VmHWM 4480 KiB
for one-pass (32 samples, 31.99 s), 9344 KiB for per-set indexes (11 samples,
11.01 s), and 9472 KiB for baseline (15 samples, 15.11 s). VmHWM is sampled
while the process exists, so its final peak could be higher. All comparisons
return success; the lab restores client and cron and verifies the boot and config
hashes. The one-pass implementation saves memory in this observation but is
still not adopted because of its duration and CPU cost. These are diagnostic
experiments, not a mixed-workload LiteClient pass. The evidence archive
SHA-256 is `9b3bbc786497acbc48c4b1d42da66dac4cbfbf4c27ee81b8726997b327f88c3c`.

A fourth candidate compacts the kernel snapshot before building ownership
indexes, retains every set name, and indexes only nonempty element lists. In
the same alternating native comparison, observed jq VmHWM is 5764/5680 KiB
over 12 samples per candidate run, versus 9344/9472 KiB over 15 samples per
baseline run. Wall times are 11.55/11.63 s versus 15.11/15.07 s. The snapshot
and policy are 422639 and 142147 bytes. The candidate passes all four checks;
the lab restores the original services, confirms boot and config hashes, and
leaves the installed router scripts unchanged. The evidence archive SHA-256 is
`9e5415fec079a74e6c60cee3a071ffc8012fcdcba7f9d14ca8572242f25fda99`.
This is a comparison of the consistency function on one device snapshot, not a
completed LiteClient mixed-workload run. Router candidate 1.38.28 incorporates
the same algorithm; its CI and rollout status are tracked separately.

A mixed REALITY run on the 4A left the installed client services and cron running
and separately exercised the candidate policy check. It verified 153 rounds of
four concurrent 64 KiB responses, then the resource guard stopped the client
when sampled MemAvailable fell to 2608 KiB; round 154 consequently failed to
connect. Sampled client RSS peaked at 2864 KiB over 220 samples. Five candidate
policy checks succeeded and one returned lock-busy (75), which is not a
successful readiness observation. The installed diagnostics also remained
active, so this run may include both old and candidate checks; it does not
represent a deployment of the candidate and does not establish the source of
the memory drop. The test failed its safety criterion. Boot and saved config
hashes matched afterward, all six client services remained running, and AWG
HTTPS returned 200. Evidence SHA-256:
`1cc134d0f6ae2e25d32aafd7558caa17721b783a83381b2f851029082947d511`.
A second mixed run temporarily suspended only the idle installed diagnostics
watcher, substituted the candidate consistency check for this test, and kept
other client services and cron running. The watcher resumed afterward. The guard
stopped the client at round 37 after 36 rounds (144 responses) passed; sampled
MemAvailable reached 3700 KiB and client RSS peaked at 2840 KiB. Two candidate
policy checks succeeded. A separate low-memory sampler observed nft at 7996 KiB
RSS immediately before a 3392 KiB MemAvailable observation; it did not capture
the nft command line or prove which caller owned the process. Both samplers are
independent and can observe different minima. This run is also a failed mixed
safety test, not a deployment or proof of the root cause. Boot and saved config
hashes matched, all six services ran, and AWG HTTPS returned 200. Evidence
SHA-256: `b1440f877cf45149259f2437193ec2024b19792d3b141affabfc14ff83409623`.
A subsequent read-only process observation identified the full-table nft dump
as a child of the client `domain_cache` service (two independent invocations).
The first reached 8096 KiB sampled RSS. A separately invoked, identical
`nft -j list table inet p4vpn` command reached 7804 KiB sampled RSS and produced
a 422639-byte snapshot. Thus reducing jq allocations does not eliminate the
nft peak; the earlier failed test did not record its process parent, so its
specific invocation is still not attributable with certainty. On the same
router a trial of 200 distinct per-set nft reads took 2.75 s after enumerating
2948 owner set names; it did not verify a complete consistent snapshot or
measure the entire operation. No alternative was adopted from this partial
measurement. All services and AWG HTTPS were checked afterward.
Further exploration on the same 4A found that `nft -j list sets` still
reached 7228 KiB sampled RSS and included sets outside the policy table. A
batch file containing 200 individual `list set` commands failed with missing
set errors although individual invocations had worked; this is not a usable
replacement. A preliminary enumeration pipeline also aborted jq and its
pipeline status obscured that failure; it was rerun with separately checked
commands. No production change was derived from these experiments. Afterward
the original boot ID remained, all six client services were running and HTTPS
through AWG returned 200.
A non-production raw-netlink Python prototype was evaluated in an isolated
Linux network namespace. It enumerated the policy table's sets and streamed
individual element dumps, checking netlink framing, sequence, interrupted dump
and error responses. For a fixture with empty and populated IPv4/IPv6 owner
sets, parsed addresses matched `nft -j`; a second fixture with 2948 empty sets
also matched (0.38 s on the container host, not a router measurement). Kernel
interval sets include internal boundary/sentinel entries, so the prototype
explicitly skips the IPv4 aggregate: it does not establish equivalence for
ranges, live concurrent changes or complete policy snapshots. The prototype is
not installed, shipped or a device-memory measurement. Further work needs
interval decoding, a defined consistency barrier and tested target binaries.
In the same isolated prototype, the nftables generation ID advanced from 3
to 4 on adding an element and to 5 on deleting it. This is evidence that the
ID detects those two explicit updates on that kernel, not proof that it detects
all changes relevant to a multi-dump snapshot, such as expiry or every OpenWrt
kernel version. No consistency guarantee or production implementation follows
from this fixture alone.
A later prototype checkpoint decodes the kernel's IPv4 interval boundaries and
compares their ranges with `nft -j` in isolated fixtures. Empty sets, /0,
0.0.0.0, 255.255.255.255, a CIDR, an explicit range and three disjoint ranges
matched. A synchronized fixture changes an owner set after the initial nftables
generation read; the prototype rejects the result and emits no snapshot.
Another fixture demonstrates that element timeout expiry did not advance the
generation ID on the tested host kernel. The prototype therefore rejects
timeout on policy sets instead of treating the ID alone as sufficient. A
read-only 4A observation found 2951 policy sets with no flags and one interval
set, with no timeout flags at that moment. Generation changes on unrelated
nftables transactions may also invalidate a capture and are not yet measured.

These are host fixtures, not proof of all kernel interval encodings, sustained
concurrency, device RAM or production behavior. The Python prototype is private
scratch code, is not installed on the router, and does not establish the API,
packaging or correctness of a cross-built component. Its SHA-256 is
`172736a1ee3d3518ccba81c874dd162f4a6c0c7e44d5371036ad08a84b201251`.
A separate scratch C prototype enumerates only policy set names through a raw
netlink GETSET dump; it is not the snapshot implementation. A static MIPS
binary compiled with the OpenWrt 25.12.5 MT7621 toolchain was copied to the
4A temporarily and its SHA-256 checked before execution. Four runs under the
policy lock each returned 2952 names in 0.03 s; process-reported `/proc/self/status`
VmHWM was 100, 96, 100 and 96 KiB. Its sorted names matched the names from a
subsequent `nft -t -j list table inet p4vpn` observation. These figures cover
only name enumeration, exclude kernel allocations and do not include elements,
interval decoding or generation consistency; they cannot be compared to the
full snapshot's peak as a complete replacement. The binary was not installed;
temporary device files and the download container were removed. The boot ID
was unchanged, six client instances were running and AWG HTTPS returned 200.
MIPS binary SHA-256:
`e874240b41646e935754cfb9a3f7ba71a2e284893cb0e2a40c64948e62890c8f`.
A later scratch C element reader was cross-compiled for MIPS. An isolated
fixture compared its raw IPv4, IPv6, empty-set and IPv4 interval-boundary
results to explicit expectations and the Python netlink probe; a missing set
failed. On the 4A, while holding the policy lock, an experiment invoked the
reader separately for each of 2951 owner and IPv6-union sets. Its 729 emitted
address records matched `nft -j` contents both before and after the reads;
the per-set reading phase took 12.19 s. This timing excludes the two full nft
snapshots, JSON normalization and sorting. The before/after comparison does
not rule out an ABA change and is not an atomicity guarantee. The IPv4
aggregate, full generation validation and target peak memory were not measured
by this experiment. An earlier attempt used a BusyBox sort form that emitted
rather than sorted the input and failed; it is not counted as a pass. The
corrected test left no device files, the original boot ID remained, all six
client services were running and AWG HTTPS returned 200. The temporary element
reader binary SHA-256 was
`e9736f38e7142ac880dca5efd4f5b5cdea4e1110aeb3b37a04a64909656e6be8`.
A scratch MIPS experiment reads all set element dumps in one process rather
than starting one process per set. On 4A it read 2952 sets in 3.59 s with a
92 KiB process VmHWM; 729 owner/IPv6-union address records matched `nft`
observations taken before and after. Its 920 raw IPv4-union boundary records
matched a separate netlink reader, not a decoded comparison against nft. The
measurement excludes set-name enumeration, the two nft snapshots, validation,
sorting and kernel memory. A second build adds a generation check around the
multi-set element reads: an isolated fixture forced a mutation between a read
and the final generation check and the process failed explicitly. On 4A this
second build took 3.60 s and reported a 92 KiB process VmHWM with the same
729 owner records and 920 raw boundaries. The independently enumerated set
names precede the generation check, and the C prototype does not yet check set
flags or decode the aggregate, so this is not a complete or installable
consistent snapshot. No production files were replaced. The original boot ID,
client services and AWG HTTPS were verified; device files and the download
container were removed. Generation-check build SHA-256:
`aa7e98493b6e6f7b13ae9309d4bcc05b6be6edfb8549638bf3a5319cdd28c7b0`.
A subsequent scratch MIPS prototype brings enumeration and element reads under
one nftables generation check and explicitly validates each selected set's key
length and flags, refusing timed or unexpected set types. It emits a separate
record for every set, including empty sets, and refuses a missing IPv4 or IPv6
aggregate. Isolated fixtures cover empty sets, missing aggregates, unexpected
timeout flags and an explicit concurrent element mutation; the mutation makes
the process exit nonzero. On 4A, one temporary run under the policy lock took
3.76 s and reported 112 KiB process VmHWM for 2952 sets. The names and 729
owner/IPv6-union records matched a bracketing nft snapshot; 920 raw IPv4
interval boundaries matched the separate netlink element probe. This is not a
comparison of decoded intervals with nft on the device and excludes tmpfs
staging, kernel allocations, consumer conversion and mixed workload. A failed
capture may already have emitted partial records: a real consumer must stage
output and accept it only after successful exit. It is a private prototype,
not an installed or CI-tested policy implementation. Device files and the
download container were removed; boot ID, six client services and AWG HTTPS were
verified. MIPS binary SHA-256:
`a4237ca6d3f249c702bef2c7826fac6e28e23b2e2633e1ac60f7d0ef77d7890a`.
The same scratch snapshot source was cross-built with the OpenWrt 25.12.5
Filogic aarch64 toolchain and exercised read-only on the AX3000T running
OpenWrt 25.12.5. Under the policy lock, 2888 set names and 15798 owner and
IPv6-union address records matched nft before and after the capture. The 6310
raw IPv4-union boundary records matched a separate netlink reader; they were
not decoded and compared to nft on the device. The snapshot process took
1.70 s and reported 108 KiB VmHWM. This excludes kernel allocations, tmpfs
staging, output conversion, control snapshots and concurrent workload. The
prototype checks nftables generation but is not an installed snapshot consumer.
The original boot ID and six running client service instances were checked after
the read; temporary files and the download container were removed. Aarch64
snapshot SHA-256:
`a297e5dfbfc8132b269a70d0af559e7e036aa41910a3d428f7de52a083051ac8`.
With the owner's test-router authorization, a separate isolated REALITY soak
temporarily pauses client, cron and AWG on the 4A, preserving configuration and
restoring their original services on exit. Using the same MIPS client and LAN
stand, 200 rounds of four concurrent 64 KiB requests complete with all 800
response hashes matching. The client and lab both exit zero. During 283
one-second samples, minimum MemAvailable is 12984 KiB, peak sampled client
RSS 2804 KiB and maximum client thread count four. This is an isolated
lifecycle and concurrency observation, not a throughput comparison, mixed
router workload or a no-leak guarantee.

The original boot ID and all nine recorded configuration/script hashes match
after restoration; client's six procd instances and cron are running again, AWG
is up, and an HTTPS request through AWG returns 200. No user-router service
is changed. The native evidence archive SHA-256 is
`f24028e673d21968ff86e451e0c06e0b9db7f9e14dbaeb41c97bd55516b9d67e`.

The current source was also compiled with `LC_SPIDER_PROFILE=1` for a separate
host-only diagnosis of bigbody, gzbody, latebig and closeafter. All eight
paired probes finish and the container exits zero without OOM. Across the 20
C retry connections, medians from profile base to opening-Write completion,
Do-thread entry and request-Write completion are 49.6, 148.29 and 388.43 us;
the median per-connection opening-to-request interval is 343.67 us. The wake
field is zero in eight samples and is not treated as a measured duration.
These are instrumented, dependent samples, not an ordinary-build timing gate;
the intervals include protocol work, scheduling and stand I/O. They do not
identify a single cause of the gap or justify changing a wait or the wire.
The profiled executable SHA-256 is
`77ac9de12e7bf6c13e70bd1b98d10ec205e344ef277a7daa94c46408b380afb5`.

A separate ordinary-build host diagnostic repeats gzbody in both client orders,
without overlapping the device workload. Each role has five related retry
connections per round. First-HEADERS medians in microseconds for Go / C are
445 / 508 and 271 / 381; neither role sends CANCEL in these 20 connections.
The C and reference executable hashes match the previous task-retirement
comparison. These small dependent samples are not G2 acceptance and do not
identify a cause; the G2 gate, native spider wire test, long soak and mixed
router workload remain open. Raw logs and receipts are retained outside the
workspace in a private temporary directory.

### Work-bounded Hysteria receive notifications (O2), 2026-10-26

`lc_rxopen_hand` no longer broadcasts to the whole opener pool for an empty or
small batch. An empty batch emits no notification; fewer datagrams than workers
use one signal per datagram; a larger batch retains the broadcast. Pool size,
keys, slot ownership, packet-number reconstruction, ordered hint consumption and
release/acquire completion are unchanged. Stop still broadcasts to every worker.
The sender's existing 150 us active wait is unchanged.

The fixture forces a four-core pool for deterministic notification boundaries and
compares 200 batches per cipher, now ranging from zero to 32 datagrams, with
serial opening. All 600 batches match for ChaCha20-Poly1305, AES-128-GCM and
AES-256-GCM, including broken tags. Empty/single/small/full notification checks
and whole-pool shutdown pass. Three isolated mutations (whole-pool notification
for every batch, no notification and one signal for every nonempty batch) fail
the intended assertions; the restored control passes.

An isolated prototype comparison runs six alternating C/C rounds on one x86-64
host, server, credentials and configuration. Each measured case sends and
byte-checks 32 MiB echoed back; four-stream cases use four 8 MiB transfers.
All 24 cases pass. CPU ticks have 10 ms resolution. Median baseline/prototype
CPU is 0.59/0.57 s for one stream and 0.48/0.475 s for four; elapsed medians are
0.276/0.268 and 0.249/0.251 s. These small mixed differences do not establish a
speedup; the deterministic result is the notification bound. A separate trial
removing the sender's GSO-state read mutex shows no benefit and is not adopted.

The final source passes the complete offline `make check`, including both plane
selections for MIPS/AArch64 and QEMU crypto checks. The first attempt lacks the
pinned x509-limbo test corpus in its cached image and is retained as failed;
preparing that exact module, as required by docker/Dockerfile, precedes the
successful offline retry. Focused ASan/UBSan and TSan runs instrument the changed
receive-pool source and fixture, with ordinary objects for other modules.
TSan requires ASLR disabled only in its disposable test process; its preceding
default-mapping startup failure is retained. An attempted whole-object sanitizer
build stops on an unrelated conversion warning in fp/fpt.c and is not counted
as a pass. No warning is disabled and that parser is unchanged.

The final cross-built fixture and client also run temporarily on test 4A,
OpenWrt 24.10.8 / kernel 6.6.144. The fixture exits zero in 5 s; sampled peak RSS
is 1960 KiB and minimum MemAvailable 10660 KiB. The actual client passes the
closed-UDP-port lifecycle described below: idle close, immediate stale-request
failure, one 5.14 s failed handshake and recovery on the next request after
server restart. All seven successful 64 KiB responses match SHA-256. Client
sampling observes peak RSS 3444 KiB and minimum MemAvailable 4868 KiB over 68
samples. These are observations, not product limits or precise peaks.
Boot and AWG identities remain unchanged; no installed client is replaced.

Executed MIPS client SHA-256:
`fc6c744d2224cb87a994992e10b342855e31b5b77a5390c9c0c1f3041fb31ba9`.
Fixture SHA-256:
`d2641b96bb992bd289a2f5472646deea4eae5a7a940f11f33215ddfdb3b1dba3`.
Retrieved device archive SHA-256:
`4c086f78a4302759704700816880424eb7257c7f204e215662080198b5ffce06`.
Private evidence is retained outside the workspace as
`diagnostics/rx-wake-validation-20261026`; prototype measurements are separate
under `diagnostics/rx-wake-20261026`. The later AArch64 soak below passes;
The later isolated MIPS soak below also passes; shared-workload and G2
acceptance remain open.

### Hysteria soak and partial worker-start failure, 2026-10-26

The O2 client completes a bounded native five-minute run on the test AX3000T,
OpenWrt 25.12.5, without replacing any installed client. One temporary process
returns 277 responses in 301 s: 64 KiB normally and 1 MiB every tenth request,
44695552 bytes total. Every response matches its expected SHA-256. There are
no request errors, idle closes or failed QUIC handshakes. The pinned Hysteria
server runs in a disposable LAN container; this is a lifecycle check, not a
throughput comparison. Boot and AWG interface identities remain unchanged.

One-second sampling gives 298 samples, minimum MemAvailable 20592 KiB and peak
sampled client RSS 3076 KiB. The kernel's final VmHWM is 3692 KiB, higher than
the sampled RSS peak; final VmRSS is 3060 KiB. Neither sampling nor a five-minute
run proves an absence of leaks or establishes a product memory limit.
Executed AArch64 client SHA-256:
`318bf0284a447085d7a34479f27ec020bc610c6b477a4ba93c2dbd7399346e61`.
Device evidence archive SHA-256:
`0d1cfab164732ffd941ff5ea86f335239c9d5f1d37972ae9be7c1796db6f1751`.

Two MIPS attempts with the preceding O2 binary remain failed safety-stop runs:
17/14 checksum-verified responses, then failure of request 18/15 as MemAvailable
reaches 3784/4072 KiB. Client RSS peaks at 3424/3500 KiB; concurrent jq snapshots
show 8416/9016 KiB. Available memory recovers after those processes finish, but
these observations do not isolate the complete cause of pressure. Background
services are not stopped, the 4096 KiB guard is unchanged, and no run is resumed
or pooled with the AArch64 result. An earlier setup failure, before any response,
is also retained: extracted stand binaries lacked executable permissions.
MIPS device evidence archive SHA-256:
`7d4424e9fc5a9cf789e6d2fafa279cac6bc75365a61826703379804b22b3b00d`.

The receive-pool fixture now injects EAGAIN at each of its three worker-creation
positions. It requires explicit construction failure, no published pool, a stop
broadcast and joins of every successfully started worker. A fresh pool must then
construct and shut down successfully. The real workers run throughout these
checks; only the selected pthread_create call fails. No production behavior or
worker count changes. Two isolated mutations, omitting unwind and concealing the
construction error, fail these assertions; the restored control passes.

The updated fixture passes the host build, focused ASan/UBSan and TSan, both
MIPS/AArch64 cross-builds and native 4A/AX3000T execution with its existing 600
byte-compared batches. The 4A execution takes
5 s, with sampled peak RSS 1976 KiB and minimum MemAvailable 20752 KiB. Boot and
AWG interface identities match before and after. TSan's first restricted-container
attempt cannot disable ASLR and is retained as a setup failure; the successful
run permits that operation only inside the disposable container. The preceding
full offline gate belongs to the earlier fixture snapshot; the new run checks the
focused fixture, device builds, shell and divergence gates, rather than claiming a
new full gate.
Executed MIPS fixture SHA-256:
`225c4d80b710e4f8a3197d8fa85d390cc030dcebad95bafd0a62ac6c44cd11de`.
Native fixture archive SHA-256:
`52413e20742dc762a541799516d782b8482a9cb8faa3195280b2afa57927d46e`.
Executed AArch64 fixture SHA-256:
`d62f96b55ae5f4638fd8a00657452ecb6b0edfd3a9fc3492b3dd1f09cbaa5ecf`.
Its native evidence archive SHA-256:
`46fdbdb3cde3d985b1e5b775c54cf1cb45afbed541619b8c1e2aab537ba29668`.
Private evidence and frozen inputs are retained outside the workspace as
`diagnostics/soak-o2-20261026`. At this checkpoint MIPS long-soak, paired native
performance and G2 acceptance remain open. The isolated MIPS result below is a
later run; LiteClient is not enabled for working connections.

### Isolated native MIPS soak and concurrent requests, 2026-10-26

The owner explicitly permits pausing AWG on the test 4A. The temporary lab also
pauses its installed VPN/control service and cron daemon, preserving configuration and restoring
their original running state on exit. Read-only process snapshots before the
pause identify a large jq under update.sh, itself started by crond. This explains
the ownership of one background task, not the entire cause of the earlier
memory pressure. External endpoints and the second router remain unchanged.

The unchanged O2 MIPS client runs against the same pinned disposable LAN server.
A five-minute lifecycle check completes in 301 s: 251 responses, 41025536 bytes,
with 64 KiB normally and 1 MiB every tenth request. Every SHA-256 matches; there
are no request failures, idle closes, failed QUIC handshakes or safety stops.
Its 294 one-second samples give minimum MemAvailable 13332 KiB and peak sampled
RSS 3444 KiB; final VmHWM is 3580 KiB and VmRSS 3396 KiB.

A separate run uses four simultaneous request generators through one client
process, with 100 requests each and the same size/checksum pattern. All 400
responses pass, 65536000 bytes in 38.90 s. This exercises concurrent TCP stream
creation/reuse on the shared Hysteria connection, following the pinned reference
`vendor/hysteria/core/client/client.go::TCP/openStream`. Six client threads are
present in the final snapshot, including the existing receive opener pool.
Its 39 samples give minimum MemAvailable 10668 KiB and peak sampled RSS 3988 KiB;
final VmHWM is 4000 KiB and VmRSS 3588 KiB. This scripted lifecycle workload is
not a paired throughput measurement or a statement of the router's maximum rate.

The original 4096 KiB safety guard is retained. The two runs are separate, and
the earlier mixed-workload safety stops remain failures. The isolated results
do not prove coexistence with the router's background tasks or absence of leaks.
The first lab setup also remains failed: a child of the stopped watcher stayed
alive and the driver restored the services instead of starting the test. The
successful driver signals only saved pre-stop watcher PID/start-time identities;
it does not change the installed service or kill unrelated processes.

Both successful runs exit zero, keep the same boot identity and preserve the
checksums of network/firewall configuration, cron and installed router scripts.
AWG is intentionally taken down and up; interface identity is therefore not
asserted unchanged. After restoration its original peer/endpoint is present and
HTTPS through AWG returns HTTP 200. All temporary clients, fixture containers
and device files are removed; no reboot or installed LiteClient activation.
Executed client SHA-256:
`fc6c744d2224cb87a994992e10b342855e31b5b77a5390c9c0c1f3041fb31ba9`.
Serial device evidence archive SHA-256:
`c0ed183f94272c5f2600608a91341f95b933586186ba5766d507aa3c8cc7ae2a`.
Parallel device evidence archive SHA-256:
`8bf40c64aedfb887b047cbf1b76ab0122348d68ce0f07fa34d2b444f7ec9acaa`.
Private evidence and drivers are retained outside the workspace as
`diagnostics/mips-soak-20261026`. Isolated native MIPS soak is now verified;
shared-workload integration, paired native performance and REALITY G2 remain open.

### Closed UDP port, initial failure and bounded soak, 2026-10-26

Before the O2 refinement, the preceding MIPS client is checked with the test
server process terminated, not paused. The fixture verifies the absence of its
UDP listening socket. The client survives ICMP rejection until its 40005 ms idle
timeout, makes no unsolicited reconnection for another 20 s, fails the stale
request in 0.09 s and one new connection attempt in 5.13 s. Restarting the test
server lets the same process return six checksum-verified responses. A fresh
client against the closed port exits 1 in 5.07 s without opening its listener.

A separate five-minute baseline lifecycle soak does not complete. It verifies
192 responses (31260672 bytes), then the unchanged stand safety monitor stops
the client at request 193 when MemAvailable reaches 3848 KiB. Client RSS is
3468 KiB in the last sample; the sampled peak is 3536 KiB over 226 samples.
The failed request is retained, not converted to success. Boot and AWG remain
unchanged. This does not prove a client crash, a memory leak or the cause of the
router's overall memory pressure; it also does not pass long-soak acceptance.
The refined client's later MIPS attempts also stop at the resource guard;
the separate AArch64 result is recorded above.
Private evidence is retained as `diagnostics/closed-port-20261026`; archive
SHA-256 is `282732f10e22bfc2e1cafef239ab07da8a51a2939ef45d761d4d25ff0e78cafe`.

A separate matched current Go/C loopback comparison has six alternating rounds
and 24 byte-checked measured cases, with 32 MiB echoed per case and six online
CPUs (Go GOMAXPROCS=6). Median Go/C CPU is 0.22/0.605 s for one stream and
0.215/0.485 s for four; elapsed medians are 0.136/0.276 and 0.144/0.252 s.
This C baseline predates the notification refinement. The CPU gap is still
present on this host; these numbers are not router rates, are not pooled with
the earlier LAN/profile runs and do not attribute the complete gap to one cause.
Raw evidence is under `diagnostics/current-pair-20261026`.

### Native Hysteria silent-path recovery, 2026-10-26

A fresh MIPS build of the current source runs as an isolated temporary process
on the test 4A (OpenWrt 24.10.8 / kernel 6.6.144). Its 316 source/test manifest
entries match before and after the build; the copied and executed binary has
SHA-256 `8b727cec477062bba8d9ee6ac62994ca78af05b1c85c4b082dd8c8cd6fc1f685`.
The pinned reference Hysteria server runs in a disposable LAN container, with
the preceding stand's fixture credentials and certificate. No external endpoint,
installed client, router service or network configuration is changed.

After a checksum-verified 64 KiB warmup, only the test server process is paused.
The native client reports idle close after 40004 ms without accepted peer input
and makes no new connection attempt during a further 20 s without requests.
The stale-client request fails in 0.10 s; the next request makes one connection
attempt and fails in 5.14 s. Once the server resumes, the same client process
returns the next 64 KiB response in 0.20 s and five further responses in
0.12-0.13 s. All seven successful responses, including warmup, have the expected
SHA-256. This follows the pinned
`vendor/hysteria/core/client/reconnect.go::clientDo`: a ClosedError invalidates
the stale client; a subsequent request reconnects, without an automatic retry
of the failed request. The test exits zero and leaves boot/AWG identities unchanged.

One-second sampling over 68 samples observes peak client RSS 3472 KiB and
minimum MemAvailable 7964 KiB. These are observations, not product limits or
precise peaks. The first attempt is retained as a failed safety-stop run:
MemAvailable reaches 3492 KiB while client RSS stays at 3456 KiB in its last
samples. A background domain-policy jq process appears in the preceding process
snapshot; that correlation does not isolate the cause of the memory dip.
A second harness attempt refuses a symlinked password file before connecting;
the successful attempt uses a regular private file, preserving that security
check. The existing 4096 KiB stand safety threshold is unchanged.

This closes the previously uncompleted native silent-path recovery scenario,
not a long soak, native closed-port acceptance, a paired throughput comparison
or G2. Private drivers, source hashes, failed attempts and successful raw logs
are retained outside the workspace as `diagnostics/native-recovery-20261026`.
The retrieved device archive SHA-256 is
`29fc93c12a15f891a3c1cde89cb35aa3ed203ece11b9d6d06c35e215d43cecf7`.

### Hysteria sender CPU profile, 2026-10-26

A separate x86-64 diagnostic run sends and echoes sixteen byte-checked 32 MiB
transfers through the pinned Hysteria server and loopback echo target. All
sixteen loader processes exit zero: 512 MiB sent and 512 MiB verified back.
The C build uses the same 316-entry source/test manifest and ordinary size
optimization, with debug information added; its SHA-256 is
`dfd0351498aaf6bcb1322fd3213a2edd833006746390f79f400aaeb74ea82faa`.
Source manifests match before and after. This is a diagnostic on the Docker
Desktop Linux host, with eight client threads, not a router measurement or a
paired Go/C performance comparison.

Linux perf's cpu-clock sampling at 199 Hz captures 5053 samples with no lost
samples. The sender `writer` accounts for 22.72% of sampled CPU. Symbol offsets
mapped to the same binary's objdump source/disassembly put 22.50% in the
`sendq.c::await_awake` atomic/pause loop. AES-NI ECB accounts for 3.46% and
`x86_product` for 1.98%; these flat samples do not apportion all crypto or kernel
work. Scheduler/kernel costs are also substantial and need stack-level diagnosis
before attributing them to a particular queue or algorithm.

The active wait is the existing 150 us owner-approved send-queue policy, documented
in `src/quic/sendq.{c,h}`. The pinned `vendor/quic-go/send_queue.go::Run` consumes
the send channel independently; Go's scheduler and this pthread executor have
different wakeup mechanisms. This profile identifies a present CPU cost, not
the causal size of the earlier Go/C delta. Removing the active wait would also
reopen the previously measured datagram-spacing question. No spin duration,
worker count, cipher, protocol default or production wire behavior changes here.

The initial perf output on the Windows bind mount fails and is excluded. The
retained final capture writes inside the Linux filesystem; the attached recorder
is deliberately stopped with SIGINT (exit 130), and report/script replay exits
zero. `perf annotate` crashes in the diagnostic environment; the offset mapping
uses successful `perf script` and objdump instead. Earlier harness failures and
all raw logs remain private under `diagnostics/native-recovery-20261026`.

### Successful authenticated traffic and recovery, 2026-10-26

This checkpoint prioritizes authenticated REALITY/Hysteria traffic, resource
cost and recovery. It does not change the spider fingerprint, protocol defaults,
G2 thresholds or installed router software. The server and both Go clients
come from the pinned vendor sources. The isolated LAN stand uses disposable
fixture credentials/certificates and local echo/HTTP targets; no live node or
router service, firewall, route or installed client is changed.

On the x86-64 host, three alternating rounds compare each C/Go client with one
32 MiB echo transfer and four concurrent 8 MiB echo transfers. The loader checks
every returned byte against its offset-dependent pattern. All 24 cases exit 0:
768 MiB sent and echoed, without truncation or mismatch. The first run gives
both clients a two-CPU budget; Go uses GOMAXPROCS=2 while C observes six online
CPUs for its worker allocation. Those results are retained separately.

Hysteria is then repeated without the client container CPU quota, with Go using
the six online CPUs. All 12 cases exit 0. Each row below describes 32 MiB sent
and echoed (64 MiB combined payload), with medians over three rounds. CPU is
client CPU time, excluding the loader; RSS is sampled every 100 ms.

| Hysteria / streams | Go / C elapsed, s | Go / C CPU, s | Go / C peak sampled RSS, KiB |
|---|---|---|---|
| One | 0.86 / 0.87 | 1.04 / 1.62 | 26772 / 6340 |
| Four | 0.84 / 0.86 | 1.07 / 1.50 | 26772 / 6340 |

The C client's higher Hysteria CPU cost remains unexplained: these measurements
establish a profiling target, not a cause or an optimization. Quota and non-quota
runs are not pooled. Host echo rates count both directions and must not be
reported as one-way download speeds or router performance guarantees.

The stripped MIPS snapshot is run temporarily on the test 4A, OpenWrt 24.10.8 /
kernel 6.6.144, using stock uclient-fetch and SHA-256 of each 8 MiB response.
Three rounds per plane exercise one and two concurrent downloads; all 12 cases
(18 responses, 144 MiB) exit 0. Median aggregate download rates are:

| Plane | One stream, Mbit/s | Two streams, Mbit/s | Client threads | Peak sampled RSS, KiB |
|---|---|---|---|---|
| REALITY | 28.20 | 27.62 | 4 | 2924 |
| Hysteria | 27.39 | 30.43 | 6 | 5684 |

Direct controls measure about 33 Mbit/s for one stream before/after the run and
64 Mbit/s for two streams. The Go client is not measured on this device in this
checkpoint. Memory sampling is once per second: the lowest MemAvailable during
the completed REALITY/Hysteria matrices is 5640/7640 KiB. These observations are
neither product memory limits nor precise peak guarantees. Executed snapshot
SHA-256: `a29c282f90eead0a69bd94d7dd1b16f1f376a343795b9c99ce61aab1a1a31524`.

Host recovery follows `vendor/hysteria/core/client/reconnect.go::clientDo`:
with the server silent, C records idle close after 40 s, makes no new attempt
during the following 20 s without requests, fails the stale-client request
immediately, then times out the next request after about 5 s. Both Go/C clients
recover on the next request after the server resumes. Closing the server UDP
port does not close C immediately; its idle timer still expires after 40 s.
Fresh Go/C clients against the closed port exit 1 without listening. Stopping
the REALITY server makes both Go/C requests fail after about 12.3 s; both carry
the next byte-checked request after it restarts, without restarting the clients.

At this earlier checkpoint, native recovery remained open. The native client records idle close, an immediate
stale-request failure and a roughly 5 s handshake timeout, but the test monitor
stops it before the restored-path request when MemAvailable crosses its 4096 KiB
safety threshold. Earlier curl-driven traffic/recovery attempts also hit that
test guard; failed attempts and logs are retained, not counted as passes. The
guard is a temporary stand stop condition, not a client allocation/admission
limit. Boot and the working AWG interface remain unchanged. This is not a
completed hardware recovery or soak acceptance, and G2 remains open.

Private drivers, raw logs, input/binary hashes and analysis are retained outside
the workspace as `diagnostics/successful-traffic-20261026`. The final native log
archive SHA-256 is
`af2a9c2c3a563fe12605e85db242af0cf7714df443f3b1963b4693bd90bb8c83`.

### Request admission notification boundary (O8), 2026-10-26

Successful request-task stream admission no longer advances Do's input generation
or broadcasts to its condition. The pinned `ClientConn.addStreamLocked` assigns
protocol state without publishing a response, abort or donec notification
(`vendor/x-net/http2/transport.go:1710-1722`). The request continuation remains
immediately runnable for its writer turn. Encoding, rejected admission, cleanup
and terminal errors retain their publications; stop creates no extra progress.
This removes one unconditional Do generation/broadcast per successful admission.

Six deterministic outcomes cover normal admission and encoding, closed-connection
and concurrency rejection, lost transport, stop and OOM. The preceding source
fails the normal-admission assertion. Three isolated mutations restore the wake,
advance the generation without waking, or suppress terminal notification; all
fail the intended assertions, and both restored cleanup/tunnel controls pass.
The full offline gate, MIPS/AArch64 plane selections, QEMU crypto checks and
focused ASan/UBSan/TSan cleanup/tunnel suites exit zero.

Both cross-built native fixtures pass on test 4A, OpenWrt 24.10.8 / kernel
6.6.144. Both report elapsed_s=1 with one-second RSS sampling; sampled peak RSS
is 1244/1440 KiB and minimum available RAM 14816/14316 KiB for cleanup/tunnel.
These are sampled observations, not product memory limits or peak guarantees.
Executed binary hashes match, and boot/AWG interface identities are unchanged.
No installed client or network configuration was replaced.

A fresh fixed 80-connection host diagnosis uses four counterbalanced rounds:
baseline, candidate, candidate, baseline; each kind runs both client orders.
All builds and sanitizer runs finish before this diagnosis. The earlier attempt
that overlapped compilation is interrupted, retained and excluded. Frozen stand,
source/input guards and executed reference/candidate identities pass. Baseline
SHA-256 is `0cccdeaa0b26f07e245e6e81b7e3dd5e7b0f2dad2643b95c2e91dea0083fc8f0`;
candidate is `2ee21bff6cf4d8dc5ff7f8b8593ce6db606fb3562e2a7890593c8060270720bc`.

| Kind / scenario | CANCEL reference / C (of 10) | First HEADERS median reference / C, us |
|---|---|---|
| Baseline bigbody | 5 / 7 | 329 / 515 |
| Candidate bigbody | 3 / 9 | 289.5 / 437.5 |
| Baseline gzbody | 0 / 0 | 224.5 / 360 |
| Candidate gzbody | 0 / 0 | 239 / 388 |

The candidate still exceeds the unchanged G2 timing and bigbody CANCEL criteria.
These small dependent retry groups, differing reference counts and mixed timing
directions establish neither speed gain nor cancellation equivalence. They are
not pooled with older checkpoints. Native unit runs do not establish hardware
traffic performance. G2 remains open; per-session native worker creation and the
remaining scheduling gap still need investigation. Private raw evidence is
retained outside the workspace in `diagnostics/admission-notification-20261026`.

### Current spider critical-path diagnosis, 2026-10-26

A private diagnostic build extends the existing startup profile with immutable
request-task samples: task entry, wait/step boundaries, protocol-lock acquisition,
HPACK time and the event loop's take of the first HEADERS Write. Samples are
published before the loop logs them after the first HEADERS reaches the socket.
Only the isolated diagnostic copy is instrumented; production source is unchanged.
The ordinary build remains byte-identical to the preceding stream-admission
candidate, SHA-256
`0cccdeaa0b26f07e245e6e81b7e3dd5e7b0f2dad2643b95c2e91dea0083fc8f0`.

Four counterbalanced stand rounds cover bigbody and gzbody, eighty connections
total: twenty diagnostic C connections, twenty ordinary C controls, and forty
reference connections in their separate paired groups. Both profile rounds
contribute ten complete samples. Source, stand, input and executed-binary
identity checks pass; the build and stand containers exit zero without OOM.
The twenty instrumented C connections have these wall-time medians:

| Phase | Median, us | Scope |
|---|---|---|
| Fetch construction | 19.00 | Browser/header/map and fetch preparation |
| Two native worker creations | 129.08 | From before the first pthread_create until the second returns |
| Request-task entry from spider base | 206.60 | Includes earlier preparation and native scheduling |
| First admission turn | 15.45 | Includes its existing generation/condition publication |
| Encoding turn | 38.54 | Includes allocation, HPACK and publication |
| HPACK within that turn | 8.43 | Encoder call alone |
| Request-step protocol-lock waits, total | 0.18 | Sum for the first request's sampled turns |
| Request notification to event-loop take | 43.92 | Task publication to the TLS owner's take, not encryption |
| Take to socket completion | 27.48 | TLS sealing and actual queued Write completion |

These phases overlap; their medians must not be added. Worker creation medians
in the two profile rounds are 130.10/126.03 us; request entry is 205.44/214.28 us.
This locates substantial startup wall time before HPACK, rather than in protocol
mutex contention. It does not establish how much a different executor would save.

The architectural distinction is explicit in pinned source:
`src/cmd/lc-tunnel/main.c:spider_worker_start` creates two OS threads per spider
session. Xray's `UClient` in
`vendor/Xray-core/transport/internet/reality/reality.go` starts the spider as a
goroutine, and `ClientConn.internalRoundTrip` in
`vendor/x-net/http2/transport.go` starts `cs.doRequest` as another goroutine.
Pinned Go 1.27.1 `runtime/proc.go:newproc1/gfget` can reuse goroutine/stack state;
there is no requirement to create one OS thread for each of these tasks.

Request admission also currently broadcasts to Do before any response exists.
The measured admission-turn duration includes that publication, but the profile
does not isolate its cost. The notification-to-take interval likewise includes
scheduling and event-loop work; it is not a measurement of eventfd alone.
Neither finding justifies merging independent Do/request/readLoop ownership,
sleeping to influence CANCEL, or adding a silent synchronous path.

Ordinary C/reference controls have bigbody CANCEL 6/10 versus 3/10 and first
HEADERS medians 482/245.5 us; gzip medians are 371.5/305.5 us. Diagnostic groups
have bigbody CANCEL 5/10 versus 2/10 and gzip 0/10 versus 1/10. Instrumentation
and post-HEADERS logging perturb scheduling, and retries are dependent. These
groups are not pooled with historical checkpoints or used for acceptance.
This is the failed-authentication REALITY spider path on x86, not established
VPN throughput or device traffic performance. G2 remains open. Private raw
evidence is retained outside the workspace as
`diagnostics/critical-path-20261026`.

### Private worker cache and executor lifetime (G2), 2026-10-26

A frozen private copy replaces native creation/join in spider_worker_start/stop
with a cache of completed tasks. It retains at most two idle native threads;
active tasks never queue behind a bounded executor. Do and request tasks keep
their separate functions, locks, start order, Write ownership and stop-before-join
semantics. No production C source is changed and this cache is not adopted.

The standalone executor fixture checks 1000 sequential jobs reusing one thread,
25 cohorts of eight simultaneously blocked jobs, a two-thread idle bound,
result/argument ownership, EAGAIN propagation and complete joins on cache clear.
Host, fully instrumented ASan/UBSan, process-local ASLR-disabled TSan, MIPS and
AArch64 builds pass. The fixture also exits zero on test 4A and AX3000T, with
unchanged boot/AWG interface identities. This is native execution of the executor
fixture, not of the complete spider prototype. Temporary device files are removed.

An ordinary paired run covers four scenarios and 160 connections in four ABBA
baseline/prototype rounds, reversing reference/C order equally within each kind.
Short unit/sanitizer/cross checks overlap this first run, so its timing is retained
as confounded diagnostic evidence and is not pooled with the subsequent run.
The separate quiet repetition has the same 160-connection design, ordinary
uninstrumented binaries and no overlapping builds or executable tests. Each
kind/scenario has ten C and ten paired Go retry connections. They are dependent
retries and a small exploratory sample, not independent acceptance observations.

Both runs validate frozen stand and executable identities before/after, complete
probe groups, one first HEADERS/PREFACE per connection, the reference SETTINGS
and connection WINDOW_UPDATE, and absence of duplicate stream-1 CANCEL. The quiet
run exits zero without container OOM. Its descriptive results are:

| Scenario | Baseline HEADERS Go / C, us | Prototype HEADERS Go / C, us | Baseline CANCEL Go / C | Prototype CANCEL Go / C |
|---|---|---|---|---|
| bigbody | 243.5 / 453.5 | 337.5 / 504 | 6/10 / 4/10 | 2/10 / 6/10 |
| gzbody | 380 / 434.5 | 292 / 320 | 0/10 / 0/10 | 0/10 / 0/10 |
| latebig | 323 / 297 | 411.5 / 339.5 | 10/10 / 10/10 | 10/10 / 10/10 |
| closeafter | 279.5 / 323 | 311 / 196.5 | 0/10 / 0/10 | 0/10 / 0/10 |

The prototype fails the unchanged diagnostic limits: bigbody's HEADERS gap is
166.5 us and CANCEL gap +40 points; closeafter's absolute HEADERS gap is 114.5 us.
The limits remain absolute 100 us and at most +10 CANCEL points. Baseline bigbody
also fails its HEADERS limit. Changing reference medians and mixed C results do
not establish a general speedup, cancellation regression attribution or G2 closure.

A separate instrumented dispatch run has forty connections, twenty per client.
Its counters are printed after each pair of task starts; timing/CANCEL from this
instrumented run is not used in the ordinary comparison. The observed task counts
are bigbody 10 created/0 reused, gzbody 8/2, latebig 8/2 and closeafter 0/10.
The first counter attempt prints only at process exit and loses that hook under
the stand's SIGTERM; it remains incomplete, with its binary and logs retained.

This limited reuse agrees with the source boundary: lc_spider_fetch_wait does
not stop at DO_END, and lc_spider_fetch_request_wait parks until work, explicit
stop or connection failure. Xray's get goroutine returns after its HTTP work
while explicitly retaining the connection
(vendor/Xray-core/transport/internet/reality/reality.go::UClient), and x/net's
clientStream.doRequest ends after cleanupWriteRequest
(vendor/x-net/http2/transport.go). Go 1.27.1 runtime/proc.go::newproc1/gfget can
reuse completed goroutine/stack state independently of the connection's readLoop.
Separating executor completion from retained transport is the next lifecycle
boundary to test; it must not cancel unfinished request cleanup or late readLoop
work. Neither source analysis nor these counters isolate the CANCEL discrepancy.

Baseline executable SHA-256:
`5cb3a8ac168899131dcbd2c40f170c7511e2f107f7af68becc503c704cfe232a`.
Prototype executable SHA-256:
`e43bafaaf69c3f8cacfaf4cec8c6c46fecba4ebd1dcdbe7833fce93e2a225ae3`.
Dispatch-only executable SHA-256:
`48b9d03a116e709e9bcfc89fb11cce7af145099b477842e85b7a1b461df8efcf`.
Native executor fixture SHA-256, MIPS / AArch64:
`c1271beaf862928b043337d428142e2784540eb371d10fc69286ec6826efdd8f` /
`6806bac3702932bb42021c5c90ba3992c89805aa05733b45424303e1db3dc83e`.
Frozen inputs, ordinary/instrumented runs, separate analyses and device receipts
are retained outside the workspace as `diagnostics/task-cache-20261026`.
Complete private evidence archive SHA-256:
`49d6fb021265294bdaa578e9d4c07b52a1f8d8d36e46ca3b3224215a08d018d7`.
G2, full-spider native traffic acceptance and shared-workload integration remain open.

### Completed HTTP executors with retained readLoop (G2), 2026-10-26

The split driver's Do wait now returns normally at DO_END; request wait returns
only after Do ends and every pending producer, owned writer and stream cleanup
has completed. Completion wakes an already parked request waiter. Each worker
publishes its terminal flag before notifying eventfd; the event loop joins it
without stopping/freeing fetch or closing TLS. There is no thread cache, timer,
new executor cap or synchronous fallback. The combined driver keeps its previous
ownership. This follows Xray `reality.go::UClient` (get returns while retaining
its connection) and x/net `clientStream.doRequest/cleanupWriteRequest` (donec
follows cleanup's final writer/error check).

The retained readLoop still handles PING, late DATA and deferred EOF. EOF after
Do completion is consumed only after accepted input and actual output Flush;
active Do keeps its previous body-before-EOF rule. The public driver verifies
normal completion with a genuinely parked request waiter, unfinished request
Flush, completed cleanup and late PING/EOF. The tunnel fixture verifies actual
encrypted socketpair I/O with EAGAIN, joined workers, late 4096-byte DATA on a
forgotten stream and combined READ/WRITE with peer EOF behind the pending ACK.
It decrypts that ACK and checks connection-only WINDOW_UPDATE. The 4096-byte
boundary follows pinned x/net `flow.go::inflow.add` and its inflowMinRefresh;
no credit threshold in the client is changed.

Validation on the frozen current source:

- Focused fetch/cleanup/tunnel suites and the complete offline `make check`
  exit zero. Both planes cross-build for MIPS/AArch64; QEMU runs 75 ARM crypto
  checks and five x86 capability profiles with 75 checks each.
- Changed fetch and embedded tunnel code are instrumented with ASan/UBSan and
  separately TSan, all passing. TSan disables ASLR only for that disposable
  test process. Strict compiler warnings remain enabled.
- Six isolated mutants are rejected by the intended assertions: retained Do,
  premature request retirement, missing completion wake, missing native join,
  missing readLoop EOF and missing tunnel EOF. Restored controls pass both
  suites; all 609 frozen source hashes match afterward.
- Cross-built fixtures execute successfully on test MT7621 and AX3000T, with
  raw cleanup/tunnel/outer-script exit codes all zero and matching binary hashes.
  Boot and AWG interface identity remain unchanged. No installed client/service
  changes are made; temporary device fixtures are removed after receipt checks.

The four-session native fixture reports MIPS RSS 1732 KiB versus 1576 KiB
baseline, returning to 1576 KiB after join; startup/lifecycle CPU samples are
4329/6688 us. AArch64 reports 1596/1432/1432 KiB and 1643/2395 us. One-second
outer samples have minimum MemAvailable 14892/36468 KiB respectively. These
bounded fixture observations are not peaks, router traffic throughput or a
production resource budget.

Retained failed attempts matter: an early EOF fixture incorrectly assumed only
Do could report EOF, and unconditional tunnel EOF draining violated an existing
active-Do barrier. Those intermediate sources are not the tested final source.
A later fixture initially expected a four-byte flow refund, corrected to the
pinned 4096-byte threshold. The first cross recipe lacked zlib headers, then
linked validation-only zlib stubs without compression symbols. Native fixture
builds instead link the real pinned zlib static library built in a private
scratch directory; vendor and product dependencies are unchanged. The aggregate
validation command therefore exits 2 even though its earlier full gate and
sanitizer stages passed; the corrected cross stage has a separate zero exit.

The first AX native run fails during fetch construction with ENOMEM. Reproduction
isolates the test's 384 MiB RLIMIT_AS: existing `paths.c::map_arena` reserves 1 GiB
of virtual address space on 64-bit, paid only as touched; the same constructor
succeeds without that limit. No arena/product-memory policy changes are made.
The private outer runner also initially used an `&&` status check that allowed
a failed test to leave outer exit zero. The failed raw receipts are retained;
the corrected runner explicitly fails on either child error or resource guard,
uses CPU/time and available-RAM guards, and both device suites then pass.
No false-success outer status is counted as evidence.

The ordinary host comparison uses the same frozen stand/reference and all
unchanged C modules. Four ABBA before/current rounds reverse client order
equally within each kind: 160 connections, ten C and ten Go retry connections
per kind/scenario. Builds and executable tests finish before this run. Stand
and executable hashes match before/after; the container exits zero without OOM.
All groups have one first PREFACE/HEADERS, reference SETTINGS and connection
WINDOW_UPDATE, with no duplicate stream-1 CANCEL.

| Scenario | Baseline HEADERS Go / C, us | Current HEADERS Go / C, us | Baseline CANCEL Go / C | Current CANCEL Go / C |
|---|---|---|---|---|
| bigbody | 325 / 564.5 | 324.5 / 362 | 4/10 / 7/10 | 4/10 / 4/10 |
| gzbody | 304 / 414 | 353.5 / 455 | 1/10 / 0/10 | 1/10 / 0/10 |
| latebig | 336 / 414.5 | 333.5 / 345.5 | 10/10 / 10/10 | 10/10 / 10/10 |
| closeafter | 341 / 264.5 | 331 / 328.5 | 0/10 / 0/10 | 0/10 / 0/10 |

These descriptive results improve bigbody in this sample, but do not close G2:
gzip's current HEADERS gap is 101.5 us, beyond the unchanged absolute 100 us
limit. The other three current groups meet both diagnostic limits; the CANCEL
limit remains at most +10 percentage points. These are dependent retries in a
small exploratory host sample. There is no native wire acceptance, statistical
speed guarantee or demonstrated production VPN-throughput effect.


Baseline / current executable SHA-256:
`8335e5e09a2b5beee6e946233380a735811d709b5b314e09db04b4e91e62dd12` /
`a0d835e87d8af8411da50e66493129e1c9126d8315289c5b0de79c04756e700b`.
Native cleanup / tunnel SHA-256, MIPS:
`024115f49492511e5da85e4d520cac4b834fee9ef6f4e18fa7ba488215be91b9` /
`c95040a17919d737f2b642e402dbd66b2672b343961855531fcec8c4b982519d`;
AArch64:
`c8dc9d28bfa036e67e176a373fb8d79ee71104095334ff6ede79d24fc4113a66` /
`b4429dba71d890870bf48879a862abcff7baa92c88c4e6ff717b6d9fa26a51c0`.
Frozen source, stage-specific logs/exit receipts, rejected mutants, native
archives and paired observations are retained outside the workspace as
`diagnostics/task-retirement-20261026`. G2, full-spider native wire acceptance
and production/shared-workload integration remain open. The worker-cache
prototype remains unadopted.

### Request-owned stream admission (G2), 2026-10-26

The split driver previously assigned an HTTP/2 stream ID on Do's turn, before
its request task ran. The pinned reference starts `cs.doRequest` from
`ClientConn.internalRoundTrip`; `clientStream.writeRequest` then checks the
connection and calls `addStreamLocked`, before acquiring cc.wmu for encoding.
Do now queues owned fields with ID zero and a retained reservation. One request
continuation admits the stream under the protocol mutex; a separate immediately
runnable continuation encodes only when the actual writer is available.
Its own opening Flush still precedes admission. No timer or scheduling delay
is inserted between those continuations.

Four new public-driver cases cover DATA for an unassigned stream, ignored reset
for that ID, stop before execution and a peer concurrency change before
admission. Existing abort, redirect and socket-EAGAIN fixtures explicitly
exercise admission before encoding. The isolated pinned Go 1.27.1 internal
HTTP/2 test also returns ConnectionError(PROTOCOL) for the unassigned DATA and
verifies that `addStreamLocked` can assign an ID while cc.wmu is held.

Three isolated mutations are rejected: the preceding early-ID source, skipping
the opening Flush, and gating admission on the encoding writer. The restored
control passes. Native cleanup and tunnel fixtures on test 4A both exit zero;
sampled RSS is 1240/1436 KiB and minimum available memory is 18632/18328 KiB.
Boot and AWG interface identities match before and after. These fixture samples
are not product limits or measurements of VPN traffic performance.
Private evidence is retained outside the workspace in the
`diagnostics/stream-admission-20261026` checkpoint. G2 remains open.

The full offline gate exits zero, including both plane selections on MIPS and
AArch64 and the QEMU crypto profiles. Focused ASan/UBSan and TSan cleanup/tunnel
suites also exit zero. The production binary and native fixtures are built
from the frozen source manifest; the final test-only alignment changes are
checked again by a separate control run.

A fresh fixed host checkpoint runs three alternating client orders, four
scenarios and 120 connections total, fifteen per client/scenario. It verifies
the frozen stand, reference and executed candidate identities before and after.
Candidate SHA-256:
`0cccdeaa0b26f07e245e6e81b7e3dd5e7b0f2dad2643b95c2e91dea0083fc8f0`.

| Scenario | CANCEL reference / C | First HEADERS median reference / C, us |
|---|---|---|
| bigbody | 5/15 / 9/15 | 548 / 660 |
| gzbody | 0/15 / 0/15 | 449 / 556 |
| latebig | 15/15 / 15/15 | 417 / 488 |
| closeafter | 0/15 / 0/15 | 405 / 296 |

Bigbody's descriptive CANCEL gap is +26.67 percentage points, above the
unchanged +10-point checkpoint limit. Absolute first-HEADERS median gaps are
112, 107, 71 and 109 us; three exceed the unchanged 100-us limit. These dependent
retry connections are a diagnostic checkpoint, not independent samples or a
per-fix effect estimate. Changing reference timing precludes inferring an
improvement from an earlier checkpoint. G2 and hardware traffic acceptance
remain open; no limit is relaxed and no historical samples are pooled.

### Separate task notification channels (O8), 2026-10-26

The fixed read-handoff diagnosis uses 40 host connections with alternating
client orders, ten instrumented connections per client and separate plain
controls. All captured CANCELs agree with each client's recorded cleanup
decision; the traced C/reference counts are 7/10 and 5/10. Median C feed-mutex
wait is 0.03 us per connection; only one Close overlaps a marked readiness
mutex wait, one TLS-open phase and one socket Read. Seven Close events are
outside those marked intervals, not proof that the loop was sleeping. The
diagnostic FIONREAD itself runs under the existing C fetch lock and can extend
waits. Buffered trace storage, atomics, clocks and kernel queries perturb
execution; this neither proves a cause for the complete G2 gap nor establishes
equivalence. Raw evidence is under `diagnostics/read-handoff-20261026`.

The source used one condition variable for two different predicates: Do input
and request/cleanup readiness. Every feed woke both native workers, including
an idle request executor. O8 separates those channels. Request notifications
follow the existing readiness predicate; terminal stop/loss/OOM broadcasts
reach both. Do's own generation and all Write/close barriers remain unchanged.
The reference uses distinct response, body and abort signals in
`vendor/x-net/http2/transport.go` (`internalRoundTrip`, `clientStream.writeRequest`)
and `vendor/x-net/http2/pipe.go` (`Write`).

Fixtures observe notification calls, hold a real request waiter inside
cond_wait, and publish unrelated input followed by ready cleanup, stop or loss.
No scheduling sleep determines the result. Separate injected initialization
failures verify cleanup of zero or one already initialized channel. Targeted
mutants restore broad notifications, wait on the wrong channel or omit the
second-channel initialization unwind. These are correctness and notification
cost checks; G2 wire/hardware acceptance remains separate. Validation and
matched wire results belong to `diagnostics/notification-channels-20261026`.

### Output ownership and request-cost diagnosis (O7), 2026-10-26

A separate fixed 40-connection host diagnosis splits initial request execution
from its wait and event-loop handoff. Ten instrumented connections observe
median first request-step cost 55.74 us and step-to-socket handoff 76.55 us.
Across each connection's two encoded requests, allocation totals have median
26.45 us, HPACK 14.03 us, explicit request-step mutex acquisition 0.69 us, and
field cloning 4.79 us. These totals are not first-request-only costs, condition
waits are separate, medians cannot be summed, and the instrumentation perturbs
execution. The uninstrumented control/reference first-request medians are
472.5/352.5 us, with CANCEL 7/10 versus 5/10. This does not establish a cause for
the entire G2 gap. Source/input hashes, executed binaries and both client orders
are checked; private evidence is under `diagnostics/request-cost-20261026`.

`fetch_take_locked` previously allocated and copied every queued Write, including
the last, before freeing the original storage. O7 transfers that last allocation
to the TLS owner instead. This removes one allocation and one payload copy per
last queued Write, without a retained buffer pool. Prefixes followed by other
Writes still copy; lengths, order, completion and errors retain the existing
contract. The reference boundary is `ClientConn.writeHeaders`'s final `bw.Flush`
in `vendor/x-net/http2/transport.go`; taking bytes does not complete that Flush.

Ownership fixtures cover detached opening bytes, concurrent-queue ownership,
separate prefix boundaries, failed completion and lifetime beyond fetch
destruction, with and without the completion barrier. Replacing the candidate
with the preceding copy implementation must fail the transfer assertion.
The two native MIPS fixtures on the test 4A exit zero, with unchanged boot and
AWG identities. The sampled cleanup/tunnel RSS is 1304/1452 KiB and minimum
available memory 12836/12644 KiB; these samples are not peak guarantees or
product memory limits. A missing-timeout preflight and a corrected fixture
expectation are retained as failures, not counted as device passes. Private
source manifests and raw results are under `diagnostics/write-ownership-20261026`.
This ownership checkpoint does not close G2 or establish VPN throughput.

### Do-first native task startup (O6), 2026-10-26

The request executor previously started before Do, although it waits for work
from Do. Start Do first, after the opening Write is submitted. This allows
request publication to overlap the second native thread creation. The reference
already executes Do/RoundTrip when `ClientConn.internalRoundTrip` launches
`cs.doRequest` (`vendor/x-net/http2/transport.go:948-966`). The request task's
existing predicate observes work published before that task exists. Worker
count, writer ownership, opening completion and stop/join semantics stay intact.

A coordinated tunnel fixture holds request-thread creation until the actual
Do worker publishes a request, then checks readiness without another wake.
The isolated request-first source fails that assertion; the restored candidate
passes. Both injected creation failures also check rollback and stage-specific
logs using the returned pthread error instead of stale errno. The final product
binary is byte-identical to the uninstrumented prototype measured below.
The second-failure case also holds creation until Do publishes the request,
then verifies stop/join and release of the fetch and wake descriptor.

A private profile separately times handshake-step calls, handoff, fetch
construction, both native creations and Do/request entry. Its extra clocks and
logging are absent from product code. Eight predeclared counterbalanced rounds
compare before/after, each with and without that instrumentation, against the
same pinned Xray snapshot (80 total connections, ten per role/build). Profile
medians in microseconds:

| Phase | Request-first | Do-first |
|---|---:|---:|
| TLS handshake-step wall / thread CPU | 629.3 / 625.5 | 636.6 / 635.3 |
| TLS completion to fetch construction start | 44.7 | 45.4 |
| Fetch construction | 23.1 | 21.2 |
| Both pthread creations | 153.2 | 139.0 |
| Do entry after creation begins | 179.7 | 99.6 |
| TLS completion to request submission | 602.7 | 493.0 |

Handshake-step time excludes ClientHello preparation and network waiting; it is
not end-to-end TLS duration. Individual phase medians must not be added to
infer a whole latency. The destination's first-HEADERS medians without profiling
are C/ref 567.5/351.5 us before and 473/430 us after; CANCEL counts are 3/6 and
5/5 of ten each. With profiling they are 587.5/387.5 and 478.5/283 us, with
CANCEL 5/3 and 7/4. Controls vary, retries are related and instrumentation may
alter later interleaving. These small groups diagnose startup ordering; they
do not establish a speed guarantee, cancellation equivalence or G2 acceptance.
Private evidence: `artifacts/lite-client/diagnostics/startup-lanes-20261026`.

Four freshly cross-built unit fixtures pass on the test MT7621, OpenWrt 24.10.8 /
kernel 6.6.144. With the final post-admission rollback case,
cleanup/tunnel/record-open/cold-gzip exit 0 in 1/1/30/1 s.
One-second sampling observes RSS 1316/1476/1568/1088 KiB and minimum available
memory 17496/17300/16244/16104 KiB. These are sampled fixture observations, not
product resource requirements or VPN traffic performance. All executed hashes
match, boot identity and AWG interfaces are unchanged, and the retrieved archive
is checksum-verified before removing the temporary directory. No client is
installed. G2 still needs fresh wire comparison and hardware traffic acceptance.

The full offline `make check` gate passes, including both plane builds,
MIPS/AArch64 and QEMU crypto checks. Focused ASan/UBSan with leak detection,
TSan and the profiling fixture pass. The additional post-admission rollback
assertion changes only the test source after that full gate; its focused,
sanitizer, profile, mutation/control and native fixtures also pass. All 317
final source/test/Makefile hashes match. Product source and executable are
unchanged between those two validation checkpoints.

A separate uninstrumented final checkpoint uses three fixed paired rounds,
four scenarios and five related retries per client/scenario/round (120 total).
The plan precedes execution, the reference/order alternates, and all frozen
stand inputs and executed client/reference/destination/probe hashes validate.
No samples are pooled with the preceding profile experiment.

| Scenario | CANCEL ref/C, of 15 each | First HEADERS median ref/C, us |
|---|---:|---:|
| bigbody | 7/10 | 341/576 |
| gzbody | 1/0 | 279/430 |
| latebig | 15/15 | 309/338 |
| closeafter | 0/0 | 345/295 |

Bigbody's 20-point cancellation gap and 235-us median gap, and gzbody's
151-us median gap, exceed the unchanged 10-point/100-us checkpoint criteria.
G2 remains open. Related retries are not independent trials; varying reference
controls prevent an individual-fix speed or regression estimate. This host
diagnosis does not establish hardware traffic acceptance. The next investigation
must address the remaining readLoop/Do/request interleaving without introducing
delays, suppressing CANCEL or weakening those criteria.

### Private gzip work and cold initialization, 2026-10-26

The fixed-Huffman table used by all C gzip decoders was initialized through a
plain shared flag, while different fetches have different mutexes. Eight cold
constructors now reproduce that table race in the preceding implementation
under ThreadSanitizer. The correction is process-wide `pthread_once`, matching
Go 1.27 `compress/flate.fixedHuffmanDecoderInit` / `fixedOnce.Do`
(`src/compress/flate/inflate.go:766-783`). No decoder can use a partly published
table. The normal Makefile gate includes `test-gozip-parallel`, which checks
eight cold workers and 256 complete independent fixed-block gzip lifetimes,
including every output byte, trailer and EOF. This is fixture width, not a
production concurrency or RAM limit. Compile/link rules declare pthread use.

Gzip construction and inflation now run under Do's private lock, outside the
fetch protocol mutex, as `gzipReader.Read` / `acquire` / `release` and
`transportResponseBody.Read` do in pinned x/net and the executing Go 1.27
internal HTTP/2 transport. Only the source callback locks pipe/flow state.
It returns an owned Read result; neither pipe compaction nor reallocation may
invalidate those bytes while inflation continues. Natural Read sizes and
owner-specific credit Flush completion remain unchanged. Stop and failure
prevent new source Reads and state transitions after private work returns.

Five coordinated Do-thread cases hold an actual gzip Read while the loop
delivers DATA/END_STREAM and PING and request cleanup runs independently.
They cover a held ACK, stop, Write failure, invalid peer settings and clean
transport EOF. Accepted EOF harvests once; stop/error cannot produce another
Read, credit or harvest. A separate ownership case compacts and grows the
pipe while the decoder retains its earlier bytes. Three isolated mutants
(retain the protocol lock, return an aliased pipe pointer, ignore source stop)
fail their intended assertions, and exact source restoration passes the suite.

Final validation exits 0: full offline `make check` with both planes and both
router cross-builds/QEMU; fetch, cleanup, tunnel and cold gzip under ASan/UBSan
with leak detection and ThreadSanitizer; and the profiling tunnel fixture.
All 317 source/test/Makefile manifest entries match afterward. The constructor
baseline's TSan failure is a reported `fixed_huff` data race, not the known
sanitizer mapping refusal. Private evidence:
`artifacts/lite-client/diagnostics/gzip-private-20261025`.

Four hash-verified unit binaries pass on the test MT7621, OpenWrt 24.10.8 /
kernel 6.6.144. Cleanup/tunnel/record-open/cold-gzip take 1/1/29/2 s and exit 0.
One-second RSS sampling observes 1332/1416/1476/1104 KiB respectively; minimum
available memory is 10284/10788/12420/18948 KiB. These are sampled fixture
observations, not precise peaks or production traffic budgets. Boot identity
and AWG interfaces are unchanged. Evidence is retrieved and checksum-verified
before temporary files are removed; no client is installed or network changed.

A separate uninstrumented checkpoint runs three fixed paired rounds in all
four scenarios, five retry connections per client/scenario/round (120 total).
All groups, destination I/O-return clocks, frozen stand inputs and executed
client/reference/destination/probe hashes validate. The plan is recorded before
the first round; there is no adaptive stopping or pooling with old samples.

| Scenario | CANCEL ref/C, of 15 each | First HEADERS median ref/C, us |
|---|---:|---:|
| bigbody | 7/10 | 310/543 |
| gzbody | 0/0 | 298/434 |
| latebig | 15/15 | 251/342 |
| closeafter | 0/0 | 271/313 |

Bigbody's cancellation gap is 20 points and its median gap is 233 us; gzbody's
median gap is 136 us. These exceed the unchanged 10-point/100-us checkpoint
criteria, so G2 remains open. Closeafter draws harvested paths in 10/15 ref and
11/15 C connections; draws are not commit counters. Related retry connections
are not independent trials. This is host diagnosis, not hardware wire acceptance,
a causal estimate of either fix or a VPN throughput claim.

### Spider task wake coalescing (O5), 2026-10-25

Do and doRequest previously wrote eventfd after every immediately runnable
continuation. They now release-publish the final result and notify once when
the task waits, finishes or fails. A whole Write still waits for the event
loop's actual completion, and both workers remain independent. The pinned
reference runs `clientStream.doRequest`, `internalRoundTrip` and
`ClientConn.readLoop` independently (`vendor/x-net/http2/transport.go`);
the changed notification policy is a C-internal optimization, not a Go scheduler
equivalence claim. No timer, arbitrary batch limit or completion shortcut is added.

The real worker-loop/eventfd fixture checks Do quiescence, own-Write wait and
error, and request quiescence/error. Four runnable phases produce one kernel
notification; the previous implementation produces four and fails the new test.
The restored candidate passes the complete existing TLS/socketpair fixture.
This measures notification count, not a percentage improvement in VPN throughput.

A fixed uninstrumented 80-connection diagnosis counterbalances client/build
order across eight paired rounds. Reference, destination, probe and executed
candidate identities are checked. Every connection retains one preface, stream
1 then 3, paths `/` then `/bb`, and exactly 5000 bytes of connection-only refund.

| Build | C first HEADERS median, us | Reference first HEADERS median, us | C/reference CANCEL, of 20 each |
|---|---:|---:|---:|
| Per-phase wake | 591 | 316.5 | 12/7 |
| Coalesced wake | 543 | 290.5 | 12/9 |

The reference moves too, and five retry connections belong to one probe group.
These samples do not establish a causal latency improvement, distribution
equivalence or G2 acceptance. Only bigbody is measured here; the existing full
acceptance criterion is unchanged. Private evidence:
`artifacts/lite-client/diagnostics/task-wakes-20261025`.

A preceding buffered trace of the unchanged cleanup decision covered 40
connections in four counterbalanced rounds. All ten traced C stream-one
decisions match their actual `peer_closed`/abort snapshot and wire reset; no
duplicate or incorrectly selected reset was found. Instrumentation changes
timing, so this is decision evidence, not a cancellation-distribution test.
Private evidence: `artifacts/lite-client/diagnostics/cleanup-order-20261025`.

The final candidate's three MIPS unit fixtures also run on the test 4A,
OpenWrt 24.10.8 / kernel 6.6.144, with matching binary hashes. Cleanup and
tunnel exit 0 in 1 s each; record-opening exits 0 in 30 s. One-second RSS
sampling observes peaks of 1312/1320/1540 KiB; minimum available memory is
21988/21248/18304 KiB respectively. These are bounded fixtures, not production
concurrency or precise peak guarantees. Boot identity and `awg0` are unchanged.
The result archive is retrieved and SHA-256 verified before removing the
temporary directory. No client is installed or router networking changed.

Final source-stable validation exits 0: the full offline `make check` gate,
including both plane builds on MIPS/AArch64 and QEMU; the tunnel fixture under
ASan/UBSan with leak detection and ThreadSanitizer; and the profiling fixture.
All 316 source/test/Makefile manifest entries match the working source afterward.
The previous notification loop fails the new eventfd assertion; restoring the
candidate passes the complete tunnel suite. Runtime-source validation is
separate from export-checker changes described below.

### Opening Write before worker creation, 2026-10-25

`spider_start` now prepares completion/task ownership and submits the opening
HTTP/2 Write before creating its two pthreads. The pinned reference's
`Transport.newClientConn` calls `cc.bw.Flush` before `go cc.readLoop`, then returns
to RoundTrip (`vendor/x-net/http2/transport.go:542-555`); `internalRoundTrip` starts
`cs.doRequest` at line 966. C no longer holds the opening behind pthread creation.
EAGAIN retains its whole Write and blocks readLoop/initial request admission until
actual completion. No input pump, Do step or delay is inserted into the startup.

The real socketpair fixture peeks at the encrypted opening when pthread creation
is called, then independently decrypts ordered opening/HEADERS records. The old
order cannot satisfy that peer observation. Both thread-creation failure cases
now use a real TLS socket and assert that the injected failure was reached;
immediate opening transport failure must attempt no threads. Existing pending
opening, early TLS input, KeyUpdate, completion and stop/join cases remain.
Focused tunnel/fetch/cleanup suites pass. Later startup error logs name preparation,
eventfd, registration, each task and the initial Write; pthread diagnostics use
the returned error code, not `errno`.

A separate fixed 80-connection diagnosis counterbalances build/client order in
eight paired rounds. Both builds use the same current GHASH and other C modules;
only main.c's startup order differs. The pinned Xray, destination and probe
identities match across every executed round. Destination I/O-return medians:

| Build | C first read, us | Reference first read, us | C first HEADERS, us | Reference first HEADERS, us | C/reference CANCEL |
|---|---:|---:|---:|---:|---:|
| Before | 222.5 | 188 | 603.5 | 316 | 10/20 and 10/20 |
| Opening first | 68 | 158.5 | 555.5 | 283.5 | 10/20 and 10/20 |

Related retries are not independent trials. Control timing moves too; these
samples do not establish scheduler equivalence, a production speed guarantee or
G2 acceptance. First HEADERS still trail the reference. The executed wire
snapshot precedes the startup error-log additions; these do not change successful
startup ordering, and their final source requires its own fixture/gate evidence.
Private evidence: `artifacts/lite-client/diagnostics/opening-before-workers-20261025`.

### x86 GHASH dispatch and G2 record-cost diagnosis, 2026-10-25

A fixed four-round diagnosis records 200 retry connections in 40 probe groups.
All destination-side cipher observations are `TLS_AES_128_GCM_SHA256`; the pinned
Xray binary and its CPU defaults are unchanged. Fifty C sessions with aggregate
record timers have medians of nine records, 5442 encrypted bytes, 63.68 us thread
CPU and 83.45 us wall time spent opening records. This is the executing network
cipher, rather than an assumption from the separate AEAD benchmark. Related
retries are not independent trials, and the timers perturb the C execution.
Uninstrumented C/reference CANCEL counts are 30/50 versus 13/50; with the C
timers they are 37/50 versus 11/50. No causal explanation of G2 follows from that.

`src/tls/ghash.c` now uses x86-64 PCLMUL under Go 1.27's `supportsAESGCM`
condition in `crypto/internal/fips140/aes/gcm/gcm_asm.go`: AES, PCLMULQDQ,
SSE4.1 and SSSE3 must all be present. The one-block multiply/reduction is derived
from pinned mbedTLS `library/aesni.c` (`gcm_clmul`, `gcm_shift`, `gcm_reduce`,
`gcm_mix`, `mbedtls_aesni_gcm_mult`). It does not change the cipher offer, record
framing, cancellation, retries or task ownership. MIPS and ARM retain their
implementations. The internal implementation difference is marked O4.

Three counterbalanced, same-host cost rounds of the final code, including its
explicit H/Y wipe, process 1677 records of 5000 bytes per algorithm. Median
AES-128-GCM open time is 35 ms before and 12 ms after; AES-256-GCM is 36 ms
before and 15 ms after. Aggregate millisecond timers are not a latency-tail
measurement. These are x86 CPU-cost results, not MT7621/AX3000T throughput.

A separate 40-connection prototype wire check counterbalances client/build
order against the same uninstrumented Xray and destination binaries. Baseline
C/reference CANCEL counts are 5/10 versus 2/10; PCLMUL is 5/10 versus 5/10.
First-request medians are 931.5/479.5 us and 959.5/526 us respectively. These
eight related retry groups do not establish a cancellation improvement or
equivalence. That prototype precedes the final H/Y wipe and expanded AAD tests.
G2 remains open; startup and request-task handoff still need investigation.

The final full offline gate exits 0, including both MIPS/AArch64 plane builds,
75 ARM AEAD checks under QEMU, and five x86 CPU profiles with 75 checks each.
Each required x86 feature is disabled independently; the gate asserts generic
dispatch, while `max` must select PCLMUL. ASan/UBSan passes the final AEAD and
parallel record-opening suites, including 2700 records per algorithm. Added AAD
lengths 1/15/16/17/31 exercise padding independently of ciphertext padding.
An isolated mutation truncating partial AAD passes the previous suite, fails the
new tag assertions, and passes again after exact source restoration. Its build
directory and mutations never touch the working source.

The final AEAD fixture also passes 75 checks natively on the test Xiaomi 4A:
exit 0, unchanged boot identity and AWG interfaces. The stripped fixture is
124900 bytes and links the real pinned mbedTLS oracle statically; ordinary
runtime link stubs intentionally omit the oracle's GCM APIs. The one-second
sampler observes 896 KiB RSS; this is not a precise peak-RSS guarantee. No client
is installed, and temporary files are removed after verified evidence retrieval.

The first native attempt did not start the fixture: the controller's arbitrary
16384 KiB free-memory admission check refused 13624 KiB. A later attempt passed
under that same check after memory recovered. That number was a harness choice,
not a router requirement or a LiteClient memory limit. The versioned device
controller now removes that unsupported admission condition; its live fixture
monitoring and process limits remain test controls, not product requirements.

Private evidence: `artifacts/lite-client/diagnostics/spider-record-cost-20261025`.
The first full-gate attempt caught a stale generated notice after updating the
attribution; its source template is corrected and the repeated full gate passes.
Initial native build attempts lacked the unit fixture's explicit include/library
settings and oracle symbols; only the successful real-oracle build ran on 4A.

### Native 4A and matched socket-event diagnosis, 2026-10-25

The current combined-readiness candidate now passes three bounded native MIPS
suites on Xiaomi Mi Router 4A Gigabit, OpenWrt 24.10.8: fetch cleanup, the real
TLS/socketpair tunnel and parallel record opening. All 316 source-manifest
entries and all three executed binary hashes match. The final device controller
records and compares boot identity and AWG interfaces itself, under `set -e`.
The router does not reboot and the installed VPN is not replaced or reconfigured.

The real-worker fixture reports four simultaneous sessions at 1756 KiB RSS,
against 1608 KiB baseline; all workers join and RSS returns to 1608 KiB. Its
startup/lifecycle CPU samples are 5291/7684 microseconds. These are bounded
fixture samples, not throughput or per-session production memory guarantees.
The record-opening suite checks 2700 records per algorithm: AES-128-GCM,
AES-256-GCM and ChaCha20-Poly1305; 2343, 2366 and 2306 respectively are answered
by the threads. Key/sequence changes and invalid work still reject stale answers.
The external once-per-second sampler is not a precise peak-RSS measurement.

The first ad hoc wrapper had not created its boot-before file after a failed
entry preflight and masked the resulting comparison error with the suite exit
code. That run is not used as proof of unchanged boot. The corrected controller
is rerun in a fresh evidence directory, with verified boot/interface comparisons.
The unchanged 16384 KiB starting-memory threshold and 4096 KiB running floor
are retained; minimum observed available memory during the final run is 11116 KiB.
Temporary test files are removed after the evidence archive is verified locally.
Private evidence: `artifacts/lite-client/diagnostics/combined-socket-native-20261025`.

A separate fixed 80-connection host experiment compares the current build and
the preceding write-first build against the same pinned uninstrumented Xray.
Only main.c differs between the two C builds; all other candidate sources,
stand inputs and executed identities are checked before and after. Eight paired
rounds counterbalance build/client order. Independent destination logs count
current C/reference CANCEL at 14/20 versus 4/20, and preceding C/reference at
15/20 versus 10/20. First-request medians are 852/571 and 797/466 microseconds.
The varying reference control and dependent retry groups preclude an individual
fix effect or equivalence claim. The cancellation gap remains observable.
G2 and real router-traffic acceptance remain open. No long 136-block experiment
or frozen measurement checkpoint is replaced by these diagnostics.
Private evidence: `artifacts/lite-client/diagnostics/current-vs-write-first-20261025`.

The same host's isolated AEAD cost probe also finds a material implementation
difference: `lc_ghash` in `src/tls/ghash.c` takes its portable path on x86,
while Go 1.27's default AES-GCM uses the available CPU instructions. Across
three fixed 1677-record rounds with identical 5000-byte inputs, AES-128-GCM
open medians are 20.87 microseconds/record in C and 1.16 in default Go.
Disabling AES/PCLMUL only in a separate Go crypto benchmark gives 76.86.
The network reference is never run with those flags. This establishes a CPU-cost
difference, not the negotiated network cipher or the cause of the cancellation
gap. The C timer has aggregate millisecond resolution. Host crypto cost must
not be presented as an MT7621/AX3000T traffic result or used to relax G2 limits.
The source and traffic snapshots remain unchanged.

### Combined socket readiness, 2026-10-25

The tunnel formerly selected WRITE with an `else if` that discarded READ in a
combined event. After a blocked Flush completed, a whole TLS response could
remain in the kernel until another event-loop turn. The dedicated spider socket
handler now services both readiness bits, retaining actual write-completion,
ClientConn writer and KeyUpdate barriers. Independent Body.Close is not delayed
behind new input. Pinned `vendor/x-net/http2/transport.go:554, :1869` starts and
drives a separate readLoop; `vendor/utls/conn.go:1390-1401` uses the input lock.
The executing Go 1.27 transport also starts its readLoop independently at
`src/net/http/internal/http2/transport.go:703` (run at :2038).

A real TLS/socketpair fixture blocks a PING ACK at actual EAGAIN and queues a
complete encrypted response from the peer. It checks the own-Flush barrier,
response dispatch in the combined event, repeated stale readiness, actual EOF,
and exactly one decrypted original PING ACK with no duplicate output. An isolated
copy retaining the preceding write-first selection fails the exact queued-response
assertion. The working source is never mutated for this control.

Fetch, cleanup and tunnel suites pass normally, under ASan/UBSan and under TSan.
The full offline gate exits 0, including MIPS/AArch64 with both Hysteria settings
and 45 ARM crypto checks under QEMU. All 316 source-manifest entries match the
working source; the isolated control and successful runs retain separate logs.
Fresh MIPS fixture binaries are built. The test 4A reports only 11724 KiB available
memory, below the unchanged 16384 KiB preflight threshold; no binaries are uploaded
or executed there. This is not hardware acceptance or evidence of a speed gain.
The earlier 40-connection diagnostic exercised no combined READ|WRITE event before
Close, so this correction does not explain that sample's cancellation gap or
close G2. No traffic measurement or long-experiment checkpoint is replaced.
Private evidence is under
`artifacts/lite-client/diagnostics/combined-socket-events-20261025`.

### Kernel readiness at spider Body.Close, 2026-10-24

A new fixed 40-connection local diagnosis compares the current C candidate with
the pinned Xray reference. Trace/plain/plain/trace rounds counterbalance client
order. Both traced clients sample FIONREAD at Body.Close entry, recording the
sample interval and explicit errors. C additionally records event-loop readiness,
worker wakes and socket read results. These are private instrumented copies;
the production source and saved long-experiment checkpoint are unchanged.

All 40 connections complete. The 20 traced connections have complete sequences,
successful socket queries, matching executed identities and independent wire
CANCEL counts. Traced C/Go CANCEL is 8/10 versus 3/10; plain C/Go is 8/10 versus
6/10. Every traced C cancellation begins before DATA dispatch. Three have bytes
in the kernel socket at Close; one Go cancellation does too. One further C case
has decrypted DATA waiting to enter feed. There are no combined READ|WRITE
events before Close in the traced C connections, so the suspected write-first
combined-event branch is not exercised by this sample. It is not established as
the explanation of these cancellations, nor ruled out for other workloads.

FIONREAD measures encrypted kernel bytes, not complete DATA or END_STREAM. Zero
does not describe TLS or parser buffers. C samples under its existing protocol
mutex; Go uses RawConn.Control without adding a protocol mutex. Clock/atomic
work, enlarged trace storage, ioctl calls and deferred exports perturb scheduling
differently. The small dependent retry groups do not establish equivalence,
performance, a fix's effect or G2 acceptance; no prior samples are pooled.

Private observer tests distinguish empty, queued, drained and invalid sockets,
and C preserves errno around observation. Instrumented C cleanup/socket suites
pass normally, under ASan/UBSan and TSan. Two observer and four reference Go
transport tests pass under the race detector. All 316 production source-manifest
entries still match. The frozen analyzer initially stops on one unmatched
parenthesis in its final JSON print statement, before reading data. A separate
syntax-corrected copy removes that character; the original, both hashes and
correction record are retained. Metrics, validity criteria and traffic do not
change and no network round is repeated. Private evidence is under
`artifacts/lite-client/diagnostics/kernel-ready-cancel-20261024`.

### SETTINGS ACK writer and parser boundaries, 2026-10-24

Pinned x/net's `processSettings` takes `cc.wmu` even for an ACK
(`vendor/x-net/http2/transport.go:2455-2471`); the Go 1.27 internal transport
used by the wrapped reference does the same. `processPing` takes that writer
only for a non-ACK. The client now preserves this distinction. ReadFrame's
parser and CONTINUATION-order checks precede writer acquisition; Setting.Valid
remains inside processSettings after acquisition. A retained control frame and
its unread tail resume only after the matching ClientConn writer is released.

Four public-driver cases cover a held request Write, fragmented ACK input,
repeated reader turns, completion, stop, failure and duplicate ACK. Eight more
cases distinguish parser/order errors from invalid settings that require the
writer. A real redirect creates two ClientConns to verify that a foreign socket
Flush does not block a local ACK. Two TLS/socketpair cases exercise actual
EAGAIN and decrypt exactly the original request, with no response to the ACK.
The preceding client fails the intended driver and socket assertions; the
implementation with writer gating before parsing also fails the malformed-frame assertion.

Adjacent older tests incorrectly expected SETTINGS ACK to bypass a held writer.
Their four fetch assertions and the real-worker socket fixture now follow the
pinned reference. The socket fixture retains ACK and PING in one accepted TLS
record instead of overwriting a subsequent encrypted PING while ACK is waiting.
Failed intermediate runs are retained separately from successful verification
under `artifacts/lite-client/diagnostics/settings-ack-writer-20261024`.
This correction does not establish the cause or disappearance of the measured
bigbody cancellation gap, a performance improvement or G2 acceptance.

The final focused suites, ASan/UBSan, TSan and full offline gate exit 0.
The full gate includes MIPS/AArch64 with both Hysteria settings and 45 ARM
crypto checks under QEMU. All 316 source-manifest entries match the working
source; fresh MIPS fixture binaries and their hashes are retained. On the 4A,
available memory fell to 12580 KiB after upload, below the unchanged 16384 KiB
preflight threshold. The device controller therefore exits 1 before executing
any suite. The temporary binaries are removed and boot identity is unchanged.
This is not a hardware pass. The failed preflight and intermediate fixture
failures remain separate evidence; no traffic experiment was started.

### Paired cancellation event trace, 2026-10-23

A separate bounded local diagnosis instruments the current C candidate and the
actual Go 1.27 `net/http/internal/http2` transport used by pinned Xray through
`vendor/x-net/http2/transport_wrap.go`. The reference hooks cover `processData`,
`transportResponseBody.Close`, `endStream` and `cleanupWriteRequest`; patching
only the legacy x/net transport would not instrument this executable.

The fixed trace/plain/plain/trace design completes all 40 connections, with
counterbalanced client order. Executed binary identities, frozen inputs, source
guards, complete trace sequences and independent destination CANCEL counts pass.
Traced C/Go CANCEL is 7/10 versus 3/10; plain C/Go is 6/10 versus 2/10.
Every traced C cancellation begins with Body.Close before DATA dispatch; this
occurs for one Go cancellation, while two Go cancellations begin during DATA
processing. Neither client cancels after its cleanup observes a clean peer end.

In two C cancellations, decrypted DATA reaches the pre-lock feed call before
Body.Close but enters the protocol state after it. One further cancellation
has 4744 bytes of an incomplete DATA frame buffered at Close. These observations
locate ordering boundaries, not the root cause of the entire distribution gap:
pre-lock elapsed time can include thread descheduling, and kernel-ready input
before TLS opening is unobserved. Do not replace that uncertainty with a mutex
causality claim, CANCEL suppression, a scheduling delay or a changed limit.

The instrumented cleanup/socket suites pass; four reference transport tests
covering cancellation, duplicate end, reset and eager end pass under Go's race
detector. Trace atomics/clock reads, allocation size and deferred log exports
perturb execution; these small dependent retry groups are diagnostic only.
G2, performance and hardware traffic acceptance remain open. No production
source or device is changed for this diagnosis. Private evidence is under
`artifacts/lite-client/diagnostics/paired-cancel-order-20261023`.

### Redirect continuation admission, 2026-10-23

Go 1.27 `Client.do` closes the old body and sends the next request without taking
a ClientConn writer (`src/net/http/client.go:726-746`). Pinned x/net then starts
`doRequest` in `internalRoundTrip` (`vendor/x-net/http2/transport.go:966`), with
stream allocation preceding writer acquisition in `encodeAndWriteHeaders` (:1221).
Do's redirect continuation must therefore not wait for an unrelated Flush after
its own Close and cleanup have completed. The request task still takes its own
cc.wmu before HPACK encoding and preserves every whole-Write completion id.

Eight public-driver cases cover a foreign PING Flush, an own queued ACK, exact
HEADERS ordering, repeated waits, stop/failure before admission and stop afterward.
Two more socket cases decrypt actual ACK then redirected-stream HEADERS after
real EAGAIN, with no duplicate request. The preceding source fails the intended
driver admission assertion; a separate preceding-source socket check exercises
the corresponding real backpressure assertion. Source snapshots and logs are
retained under `artifacts/lite-client/diagnostics/redirect-continuation-20261023`.

The fresh full offline gate exits 0, including MIPS and AArch64 with both
Hysteria settings and the 45 ARM crypto checks under QEMU. Fetch, cleanup and
tunnel pass ASan/UBSan and TSan. All 316 source-manifest entries match the
working source. The separate preceding-source socket run exits 1 at the exact
redirect-admission assertion, while the corrected socket suite passes.

On the test 4A, OpenWrt 24.10.8, cleanup, tunnel and parallel record-opening
suites exit 0 in 1, 1 and 35 seconds. The new driver and real socket cases run
on the device. Peak sampled RSS is 1512 KiB; minimum sampled available memory
is 12664 KiB, with no resource limit reached. Boot identity and AWG interfaces
are unchanged. Executed binary hashes match the fresh MIPS build; the three
temporary binaries are removed after collecting and verifying the logs.
These are bounded native correctness/lifecycle fixtures, not traffic benchmarks.

A separate fixed 80-connection local diagnostic follows the completed verification:
candidate/control/control/candidate ordering is represented by four
counterbalanced rounds, two candidate/Go and two independent Go/Go, with ten
connections per role per round. The current binary SHA-256 is
`ce13046d925914fa18474dc86590486ea84083b9a142fc4a5b3104a9f30b2173`.
All source/input guards, executed identities, probe groups and independent wire
counts pass. Candidate/Go CANCEL is 14/20 versus 2/20; Go-B/Go-A control is 8/20
versus 12/20. Each kind has twenty connections per role, not independent blocks.
This is descriptive evidence that a cancellation gap remains observable; it
does not establish improvement/regression, an individual-fix effect, equivalence,
traffic performance or G2 acceptance. The design was frozen before traffic,
no historical sample is pooled, and no automatic rerun follows. Evidence and
the frozen parser are in the same private directory's `wire/` subdirectory.

The earlier frozen experiment `measurements/20261022-172856-12470326` has finished
all 136 blocks: 38400 primary and 1360 separately reported context connections.
It fails G2. For bigbody the C/reference CANCEL counts are 2112/3200 versus
911/3200: +37.53 points, whole-block marginal 95% interval +35.47 to +39.62,
above the unchanged +10-point limit. The first-request median gaps of 109 us
for bigbody and 122 us for gzbody also fail their gate; the independent Go/Go
control passes. That frozen candidate predates the later writer/admission fixes.
Its completed results do not measure this correction and are not pooled into
another run. Hardware and wire acceptance of the current binary remain open.

### Initial RoundTrip admission behind readLoop ACK, 2026-10-23

After the opening Flush, pinned x/net starts `doRequest` in
`internalRoundTrip` (`vendor/x-net/http2/transport.go:966`). That task reserves
its stream before `encodeAndWriteHeaders` acquires cc.wmu (:1120, :1221).
The initial Do turn must therefore be allowed to queue its owned fields while
a readLoop ACK owns that writer. It still cannot encode, write HEADERS or
acknowledge the ACK. The opening Flush remains a prerequisite.

Eight public-driver cases in `test-fetch-cleanup` hold real SETTINGS/PING ACK
Writes and check admission, no HPACK mutation, exact writer ownership,
quiescent waits, stop, ACK failure and abort before encoding. Two further cases
in `test-spider-tunnel` admit the request after the ACK ciphertext encounters
actual socket EAGAIN. The peer decrypts exactly ACK then HEADERS, with original
completion ownership. Both suites reject the preceding source at their
intended admission assertions; failures are retained separately from controls.

On the test 4A, OpenWrt 24.10.8, `test-fetch-cleanup`, `test-spider-tunnel`
and `test-recopen` exit 0 in 1, 1 and 35 seconds. The new cases run on the
device, along with the record-opening pools for all three algorithms. The
four-session resource fixture reports 1644 KiB RSS and 134532 reserved bytes
per task stack; these are fixture samples, not traffic measurements or peak
guarantees. The watchdog's minimum sampled available memory is 14320 KiB and
no limit fires. Boot identity and AWG interfaces are unchanged. Temporary
binaries are removed after collecting the logs; no client is installed.

The full offline gate exits 0, including MIPS and AArch64 with both Hysteria
settings and all 45 ARM crypto checks under QEMU. Fetch, cleanup and tunnel
suites pass ASan/UBSan and TSan. All 316 source-manifest entries match the
working tree after verification. The separate clean native build produces
the same three stripped binary hashes as those executed on the 4A.

Private evidence is under
`artifacts/lite-client/diagnostics/initial-admission-20261023`. The running
136-block comparison retains its existing frozen candidate. This correction
does not close G2, replace acceptance limits or establish a speed gain.

### Cross-ClientConn request writer acquisition, 2026-10-22

`request_step` previously waited for all queued socket output before acquiring
its ClientConn's writer. The pinned x/net `encodeAndWriteHeaders`
(`vendor/x-net/http2/transport.go:1217-1255`) takes `cc.wmu`, checks cancellation,
then encodes and writes; a different ClientConn's TLS Write does not own that
mutex. The request task now uses the same per-ClientConn dependency as cleanup.
Whole Writes still reach the socket in queue order and complete only through
their original completion ids. Do's stream admission is unchanged.

Eight new cases in `test-fetch-cleanup` establish two ClientConns through an
actual public-driver redirect, complete the new opening and SETTINGS ACK, and
park an older PING Flush. They cover normal/cancelled request acquisition,
stop, foreign failure and own failure. Own SETTINGS still prevents acquisition;
an unsent cancelled request leaves HPACK and the wire unchanged. The preceding
source fails at the intended independent-acquisition assertion. Two earlier
fixture attempts stopped before that assertion and are retained as fixture
failures, not evidence against the client.

Two `test-spider-tunnel` cases also use real TLS records and a nonblocking
socketpair filled to EAGAIN. The redirected request prepares HEADERS while an
older PING ACK is blocked; the peer decrypts exactly ACK then HEADERS only after
actual socket completion. The stop case closes and reaps the session without
acknowledging the blocked Write.

The final full offline gate exited 0 on the home build server using the exact
archived Docker image, including MIPS/AArch64 builds with both Hysteria settings
and 45 ARM crypto checks under QEMU. All three focused fetch/cleanup/tunnel
suites passed ASan/UBSan and TSan. Source manifests before and after the runs
match the working source; the final gate includes the new socket cases.

On the test 4A (OpenWrt 24.10.8), `test-fetch-cleanup`, `test-spider-tunnel` and
`test-recopen` all exited 0 in 1, 1 and 31 seconds. The peak sampled RSS was
1472 KiB, minimum available memory 17120 KiB, and no resource limit fired.
The tunnel resource fixture uses four sessions on this device; the normal host
fixture remains at 64. The first attempt was refused before execution at
9712 KiB available memory; the unchanged 16384 KiB preflight passed on retry.
The boot id and AWG interface list were unchanged. Only bounded test binaries
were copied to `/tmp` and removed afterward; no client was installed.

The active full measurement is unchanged and still uses its preceding
candidate; these tests do not close G2 or establish a speed improvement.
Private evidence is under
`artifacts/lite-client/diagnostics/cross-cc-request-20261022`.

### Cross-ClientConn body-credit acquisition, 2026-10-22

Read and Close formerly waited for all socket output before returning flow
credit. Pinned x/net `transportResponseBody.Read` and `Close`
(`vendor/x-net/http2/transport.go:2173-2263`) acquire only `cc.wmu` for that phase.
The body writer now checks local ownership, and consumer readiness follows the
same writer/Flush dependency. Accounting and saved bytes still occur once;
only the matching successful Flush can return those bytes or finish the Close
credit phase. Own request/readLoop/cleanup ownership remains a barrier even
without pending socket output.

Eight cases in `test-fetch-cleanup` use the public split drivers to establish
two ClientConns through a redirect, then hold the older one's PING Flush while
the new one's body is read or closed. They check exact queued WINDOW_UPDATE
bytes and completion ids, quiescent waits, stop, foreign failure and own failure.
The common redirect fixture is shared with the request-acquisition cases.
The preceding source fails the intended body-acquisition assertion. Two earlier
fixture attempts failed setup assumptions before reaching that assertion; their
logs are retained separately, not counted as client regressions.

The preceding source fails the Read acquisition assertion. A separate isolated
mutant restoring only Close's global output barrier is also rejected at the
intended assertion, while the unmutated focused suites pass. The mutation lives
outside the working source; the first mutation runner stopped before compilation
because Python was absent from the build image. The host runner only orchestrates
Docker: all compilation and test execution still use that image.

The first TSan cleanup/fetch suites passed, but its tunnel run failed the
single-frame request fixture's eventfd assertion. A byte-identical replay passed.
That fixture started workers before filling the socket, so HEADERS could already
have completed before backpressure was installed. It now completes only the
opening through public drivers, fills the socket, then starts the actual workers.
No timeout was increased. Both the failed run and replay remain separate evidence.

The final full offline gate exited 0, including the corrected tunnel fixture,
MIPS/AArch64 builds with both Hysteria settings and 45 ARM crypto checks under
QEMU. All three focused suites passed ASan/UBSan and the final TSan run. Before/
after source manifests are unchanged and match the working source.

The test 4A (OpenWrt 24.10.8) passed cleanup, tunnel and parallel record-opening
suites in 1, 1 and 29 seconds. The peak sampled RSS was 1480 KiB and minimum
available memory 18636 KiB; no resource limit fired. An earlier preflight at
8872 KiB refused execution; the unchanged 16384 KiB minimum passed once memory
became available. The resource fixture retains four sessions on 4A and 64 on
the host. Boot id and AWG interface list were unchanged; the three temporary
binaries were removed after collecting the logs. This is native unit/lifecycle
verification, not an end-to-end protocol or speed measurement.

Private evidence is under
`artifacts/lite-client/diagnostics/body-writer-20261022`. The existing 136-block
measurement is unchanged; this correction has no measured performance claim
and does not establish G2 acceptance.

### Spurious socket readiness is not EOF, 2026-10-22

`node_fill` already distinguishes temporary lack of input (`0`, including
EAGAIN/EWOULDBLOCK/EINTR) from actual EOF (`-2`) and errors (`-1`). The old
`spider_pump(must=1)` incorrectly treated the first result as peer loss after a
readiness event. The pump now uses that return contract directly; its `must`
argument and the redundant declaration were removed from all callers.

The real nonblocking-socket fixture first completes the opening Write, then
calls the read callback with a live empty peer. The unfixed client fails at the
intended EAGAIN assertion. The fixed client preserves the connection and a
partial TLS header through repeated empty readiness; an actual peer shutdown
still publishes loss. This matches Go's `internal/poll/fd_unix.go`, `FD.Read`,
which waits through temporary unavailability rather than converting it to EOF.

The source finding stopped `measurements/20261022-170134-fc07d6c7` before its
partial cancellation outcomes were evaluated. Its stop receipt, incomplete
status and logs are retained. No partial blocks are reused or pooled into a
replacement experiment. This is a separately proven read-error boundary, not
evidence that the remaining G2 cancellation gap has disappeared.

Verification after the fix: all three focused suites passed ASan/UBSan and TSan;
the new full offline gate `checks/20261022-171246-ad989e04` exited 0, including
MIPS/AArch64 with both plane settings and the ARM crypto QEMU checks. All three
bounded native suites passed on the 4A with OpenWrt 24.10.8, including the new
real-socket regression and parallel record opening. The device driver initially
refused to start below its unchanged 16 MiB memory preflight, then ran after
memory recovered naturally; no limit was lowered or router networking changed.
Evidence and source identities are in
`artifacts/lite-client/diagnostics/spider-readiness-20261022`.

### Buffered input behind another task's Write, 2026-10-22

The readLoop now resumes accepted buffered frames and the retained feed behind a
different task's Write. `cc_run` still waits for its own opening/Flush, a complete
PING/SETTINGS needing the ClientConn writer, or DATA's actual credit Write.
Readiness inspects the pending frame, not the stale header of a dispatched ACK.
Other request/Do producer gates and whole-Write ownership are unchanged.

`test-fetch-cleanup` reproduces the original failure through public task turns:
the readLoop's PING ACK completes, Close acquires its unread-credit writer, and
an already accepted empty DATA END_STREAM must reach cleanup before its reset
decision. Sixteen cases cover buffered/held input, a following PING, stop, failed
Write, and a CANCEL selected before the reader resumes. Each successful case
checks final cleanup, exact ACK/CANCEL counts and unchanged credit. The socket
fixture in `test-spider-tunnel` exercises actual TLS and EAGAIN; the peer decrypts
one 5000-byte WINDOW_UPDATE and no spurious reset.

For bounded native resource checks, `test-spider-tunnel` can be cross-built with
`EXTRA_CFLAGS=-DLC_TEST_RESOURCE_SESSIONS=4`. Its normal host gate still uses 64
simultaneous sessions. This changes the test workload only, never the client.
The receive record-opening pools and the two spider tasks retain their own
ownership and stop/join contracts. No wire-acceptance or speed claim follows
from these deterministic tests; G2 remains open pending measured acceptance.

Verification for this snapshot:

- The unchanged offline gate passed, including both HYSTERIA settings on MIPS
  and AArch64 and the 45 ARM crypto checks under QEMU. The three focused suites
  passed ASan/UBSan and TSan. Isolated mutants restoring the global output gate
  or testing the stale frame header fail at the new END_STREAM assertion; the
  corresponding unmodified control passes. Source hashes remain unchanged.
- On the test 4A, OpenWrt 24.10.8, all three native suites exited 0:
  `test-fetch-cleanup`, `test-spider-tunnel` (four sessions), and `test-recopen`.
  The latter checked 2700 records per algorithm in 300 rounds for AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305. Four simultaneous spider sessions reported
  1676 KiB RSS, 134532-byte reserved stacks for each task and successful joins;
  these are fixture observations, not traffic benchmarks. AWG interfaces and
  uptime were preserved. No client was installed or router networking changed.
- The bounded 60-connection comparison against the frozen reference and original
  control completed with verified identities. Candidate/reference CANCEL counts
  were 11/20 versus 7/20; the separate original-control/reference groups were
  8/10 versus 4/10. Small unequal retry groups do not establish equivalence or
  improvement, and the remaining descriptive gap keeps G2 open. The full
  acceptance experiment and its limits have not been replaced or relaxed.

Private evidence is retained under
`artifacts/lite-client/diagnostics/readloop-writer-20261022` and
`artifacts/lite-client/diagnostics/readloop-wire-20261022`.
`scripts/lite-client-review/environment/verify-device.sh` is the bounded device
driver. Its first 24 MiB virtual-memory limit rejected the existing 256 MiB
`MAP_NORESERVE` path arena before exercising the regression; that failure is
retained. The driver now separates the 384 MiB virtual-space limit from the
8 MiB monitored RSS limit and the 4 MiB free-memory stop threshold. Native tests
link the pinned zlib statically for compression fixture helpers; mbedcrypto is
resolved from the router's real shared library. These test-only build settings
do not change the client or its deployment recipe.

The follow-up private cancellation trace on 22 October completed its fixed four
rounds (trace/plain/plain/trace, 40 connections). All ten traced fetches exported
complete event sequences with no dropped entries, and their five CANCELs match
the independent wire counts. One cancellation was selected before END dispatch;
four followed DATA arriving after Body.Close had broken the pipe. None followed
published peerClosed or retained buffered/held fetch input. The pinned Go
`writeRequest`, `processData` and `endStream` paths permit those observed orders.
Instrumentation changes timing; fetch events do not establish readiness in TLS
rawInput or the kernel. The evidence in
`artifacts/lite-client/diagnostics/cancel-split-20261022` is diagnostic only and
does not close G2. The full comparison keeps the existing fixed 136-block plan,
independent Go/Go control and acceptance limits.
The fresh checkpoint is `20261022-165406-d9299332`; the complete comparison was
started as `measurements/20261022-170134-fc07d6c7`. Its controller and analysis
status under `results/` are authoritative; starting it is not a passing result.

### G2 cause analysis: the readLoop cannot consume buffered frames behind queued output, 2026-10-21

Source analysis against the pinned reference only. No product code changed, no binary built, no new
measurement, no router access, no acceptance claim. The frozen measurement checkpoint and its
evidence are unchanged, and G2 stays open.

Where the reference's race actually is. `cleanupWriteRequest` does not decide the cancellation; it
repeats a decision already made in `writeRequest`, which waits for whichever of two events comes
first (vendor/x-net/http2/transport.go:1195-1214): `cs.peerClosed` returns nil, `cs.abort` returns
`cs.abortErr`. `Body.Close` is what closes `cs.abort` (transport.go:2232, 350-354).
`cleanupWriteRequest` then clears the error only when `cs.peerClosed` is already closed
(transport.go:1308-1317) and writes the reset as one `cc.wmu` plus Flush unit
(transport.go:2693-2707). Publishing `peerClosed` needs `cc.mu` alone (transport.go:2381-2395); the
flow-control refund inside `handleData` is a separate `cc.wmu` section (transport.go:2357-2367) that
is skipped entirely when the refund is zero, and the readLoop parses frames outside `cc.wmu` whatever
Writes are pending. A `Close` that broke the pipe first is the reference's own cancellation: the
failed `bufPipe.Write` sets `didReset` (transport.go:2342-2347) and `handleData` ends through
`endStreamError` (transport.go:2369-2372) without publishing `peerClosed`.

Where this client differs. `output_pending` means bytes handed to the event loop that have not
reached the socket (src/reality/fetch.c:371-374). `lc_spider_fetch_read_step` parses buffered frames
only while no output is queued at all (fetch.c:3165), and publishes a DATA terminal phase behind a
queued Write only when that DATA has no credit left (fetch.c:3148-3152). `process_data_resume`
refuses to publish reset or END_STREAM while any writer is active or the readLoop's own Write id is
outstanding (fetch.c:1663-1667, 1677-1680). The narrow per-frame gate that the reference's shape
would need already exists and already exempts DATA — `frame_needs_writer` holds the writer only for
non-ACK SETTINGS and PING (fetch.c:1981-1987), and `cc_run` defers a frame only on that predicate or
on the readLoop's own write id (fetch.c:2042-2048) — but the outer `!output_pending` condition means
no frame reaches it. `cleanup_ready` becomes ready on `abort` alone (fetch.c:434), and
`cleanup_prepare` reads `peer_closed` at the moment it decides (fetch.c:924-926, 942-943). The output
that blocks the reader is often the one `close_body` itself queued for the unread window
(fetch.c:1036-1039).

The two outcomes are separable in the source. A cancellation where the pipe was already broken is
what the reference does in the same interleaving. A cancellation where the reader had not yet consumed
frames that were already accepted, because an unrelated queued Write held the loop, is this client's
own amplification: in the reference no pending Write can stop the readLoop from parsing frames or from
publishing `peerClosed`.

Existing evidence points the same way without measuring it. The current wire diagnostic counts a reset
before the 5000-byte refund on 10 of 20 candidate connections against 2 of 20 for the reference
(artifacts/lite-client/diagnostics/request-acquisition-wire-20261007/report.txt:35); the split trace
decided CANCEL before DATA in six of ten buffers (see the follow-up section below); and the offline
suite already holds the reference order for the same scenario — the connection window for 5000 unread
bytes before stream 3, and no RST_STREAM (test/fetch/test_fetch.c:1240-1253).

What this does not establish. No run has measured how bigbody cancellations split between those two
classes, no mutant was run, no binary was built, and no causal claim is made for the whole +45-point
gap. Scheduling delays (a consumer-step yield after Close), blanket CANCEL suppression and relaxed
limits remain excluded. The two directions that would need the maintainer's explicit decision are
recorded here and deliberately not implemented: letting `read_step` consume frames and publish the
terminal phase behind a queued Write on the existing per-frame gate, which is a producer-gate
relaxation and changes what the reader publishes before another owner's Write completes; or
reordering Close's credit Write against the readLoop's continuation, which is a scheduling change.
See `CONCURRENCY.md`.

### Request writer acquisition after submission, 2026-10-07 (current checkpoint)

Do submission now queues owned fields (`request_pending`) without claiming cc.wmu.
The independent request task acquires the free writer before checking abort and
encoding, matching the pinned actual Go 1.27 encodeAndWriteHeaders boundary. A
readLoop ACK can acquire that writer first. Active HEADERS/CONTINUATION ownership,
the global producer barrier, stream allocation and header-producer reservation on
Do's turn remain unchanged. Own cleanup cannot bypass its queued or active request.

Reproduction with exact preceding production source and actual public-driver
Writes: `artifacts/lite-client/diagnostics/request-acquisition-20261007`.
Ten new cases cover PING/SETTINGS x success/stop/ACK error/abort before ACK/retained
abort after ACK, unencoded HPACK, SETTINGS accounting, quiescence, no duplicate
actions and completion without new input. Two tunnel cases use real socket EAGAIN,
whole-Write completion and peer decryption to require ACK then HEADERS. Task turns
are explicitly scheduled through real APIs, not mocked or claimed as worker parity.
The first gate's fixture lifecycle error is retained as failed evidence, not a pass:
`checks/20261007-103114/failure-reviewed.txt`.

Final clean gate: `artifacts/lite-client/checks/20261007-103339`.
Focused fetch/cleanup/tunnel and fully instrumented fetch/cleanup ASan/UBSan pass.
Full offline verification passes: 8234 `ok` lines (assertions/check summaries, not
independent test cases), mipsel/aarch64 in both HYSTERIA planes and 45 QEMU crypto
checks. All 316 source/test/Makefile guard entries match the working tree. Both
controls pass; three targeted mutations fail at intended assertions, not build
errors or timeouts: `diagnostics/request-acquisition-mutations-20261007-v2`.
Uninstrumented H0 candidate SHA-256:
924f9f70f7839dbac85dcd760a3c3393fb833e35fb947b7835a66c6cd466e3d5.

The fixed local wire diagnostic under `diagnostics/request-acquisition-wire-20261007`
has a separate plan, the same 60-connection design and unchanged original stand.
It is not acceptance or an isolated causal test. Original evidence (1022 files)
and the normal frozen measurement checkpoint remain unchanged. All fixed rounds,
guards and independent counts pass: current C/reference CANCEL 15/20 versus 6/20;
separate original-control rounds 8/10 versus 4/10. The +45-point descriptive gap
remains observable; small unequal retry groups prove neither improvement nor
regression, equivalence or causality. No current TSan,
native resource acceptance, long run or router access. G2 remains open.

### DATA terminal publication behind a later writer, 2026-10-07 (preceding checkpoint)

An additional public-driver counterexample proves that the preceding split
readLoop driver postponed saved DATA END_STREAM after its own padding Flush when
a later real body-credit Write became pending. The actual Go 1.27 processData
releases cc.wmu before its terminal error/END_STREAM actions; no second acquisition
is required. Reproduction: `artifacts/lite-client/diagnostics/data-terminal-boundary-20261007-v3`.
Two preceding fixture failures are retained, not counted as reproductions.

`read_step` now publishes only the completed DATA terminal phase behind the later
Write; its id remains untouched and the next buffered frame stays paused. There
is no producer-gate relaxation, new input admission, scheduling delay or CANCEL
suppression. The tunnel consults this API even while ciphertext is backpressured.
Twenty additional public-driver scenarios cover Read/Close, with/without a buffered
PING, own-padding and later-body stop/error, exact accounting, no duplicate wakes,
and independent cleanup observing END_STREAM before choosing cancellation. The
tunnel's real-EAGAIN fixture checks API invocation through a thin counting wrapper
that always delegates to the real driver; it does not mock its behavior.

Final isolated gate: `artifacts/lite-client/checks/20261007-101433`.
Focused fetch/cleanup/tunnel and fully instrumented fetch/cleanup ASan/UBSan pass.
Full offline gate passes: 7998 `ok` lines (assertions/check summaries, not independent
tests), both mipsel/aarch64 HYSTERIA planes and 45 QEMU crypto checks. All 316
compiled-source entries match the working tree. Both controls pass and two private
mutants are rejected at intended assertions, not timeout/build failures:
`artifacts/lite-client/diagnostics/data-terminal-mutations-20261007-v2`. The first
incomplete tunnel-link harness attempt is retained and is not a complete pass.

Original acceptance evidence (1022 hashes) and the saved normal checkpoint remain
unchanged. The short-wire result below belongs to the preceding binary, not this
new candidate. No current TSan pass or wire/native resource acceptance is claimed.
This fix proves a padded-DATA boundary; it does not prove the cause or disappearance
of the full unpadded bigbody gap. No long run, checkpoint replacement or router access.
G2 stays open; see the final gate report/receipt for binary identity and next checks.

### Independent readLoop continuation, 2026-10-07 (preceding checkpoint)

The TLS/event-loop owner now drives retained HTTP/2 input with `read_step`, taking
only the protocol mutex. In split mode Do no longer resumes that input through its
private-work lock. `spider_drain` checks the saved continuation before another take
or socket wait. Actual whole-Write completion, bounded input, KeyUpdate exclusion
and conservative producer gates remain intact; completion does not run cleanup.
Do defers transport loss while already-accepted readLoop input is pending.

Thirteen further public-driver scenarios cover two input forms (buffered frames
and a held 5000-byte tail) while real private redirect work holds Do: successful
request/ACK completion, stop at both boundaries, either Write failure, invalid
buffered DATA, and transport EOF before the accepted tail is processed. They check
exact ACK/body/credit/END_STREAM, no duplicates or self-generated idle wakeups,
and independent cleanup without fresh input. Two real socket-backpressure tunnel
cases require saved-PING resumption before waiting for a Do wake.

Final isolated gate: `artifacts/lite-client/checks/20261007-091950`.
Focused fetch/cleanup/tunnel and fully instrumented fetch/cleanup ASan/UBSan pass.
The full offline gate passes: 7489 `ok` lines (assertions/check summaries, not
independent tests), mipsel/aarch64 with both HYSTERIA planes and 45 QEMU crypto
checks. All 316 compiled-source/test manifest entries match the working tree.
Uninstrumented HYSTERIA=0 host candidate SHA-256:
`d8c7b04faa7c433255f5e33f93ad78076b4298771e221f5e74afe6856b9b8f0c`.

Both controls pass and three private mutants fail their intended assertions under
`artifacts/lite-client/diagnostics/readloop-mutations-20261007-v7`: requiring the
private Do lock, applying EOF before saved reader input, and skipping loop-owner
resumption when a later TLS header is buffered. None is counted from a timeout or
build failure. Source/input guards pass. Earlier gate and mutation fixture/harness
attempts are retained with explanations, not counted as successful verification.

The 64-session x86 fixture observes 8332 KiB RSS (2772 KiB baseline), 16335 us
startup CPU and 22585 us lifecycle CPU. The same two tasks each reserve 8 MiB
virtual stack; no third thread was added. These are not native router budgets.
The preceding TSan attempt failed before tests; this checkpoint has no TSan pass.
The original 136-block run's 1022 evidence hashes remain unchanged. Its failed
bigbody result, the preceding split candidate's short wire results below and
this offline checkpoint are separate, never pooled. The new candidate has not
passed wire or native resource acceptance. G2 stays open; the normal measurement
launcher still selects the old saved checkpoint. No long run, router access,
deployment, checkpoint replacement or commit is performed here.

#### Bounded wire check of the independent-readLoop candidate

`artifacts/lite-client/diagnostics/readloop-wire-20261007` completes the same fixed
four-round design as the preceding short diagnostic, using the new uninstrumented
candidate: 60 connections, both role orders, candidate repeats 2 and original-control
repeats 1, frozen stand/reference and no external network. No automatic rerun.
All 8650 frozen-stand source guards, 9 diagnostic input guards and executed identities
pass; the frozen parser and independent raw-frame counts agree. All 316 current
compiled-source hashes and 1022 original acceptance-evidence hashes remain unchanged.

New C/reference CANCEL is 16/20 (80%) versus 10/20 (50%), a descriptive +30-point
gap. Original C/reference in separate control rounds is 8/10 versus 3/10. Candidate
per-round C/reference counts are 6/10 versus 5/10, then 10/10 versus 5/10. Reset
before an observed 5000-byte refund remains (candidate C/reference 10/3); missing
refund observations are retained. Small unequal groups and retry/order dependence
do not establish improvement, regression, equivalence or causality. No confidence
or acceptance claim, threshold change, sample pooling or control subtraction follows.
The readLoop boundary fix has deterministic coverage, but this wire snapshot still
shows a gap. G2 stays open. Diagnose remaining producer/admission and writer/input
ordering before promoting a new long-run checkpoint; the normal launcher is unchanged.

### Independent request/cleanup task, 2026-10-07 (preceding checkpoint)

This preceding source checkpoint separates Do from request/cleanup scheduling. The tunnel opts
into two public drivers; the synchronous combined driver remains available. Ten new
split-driver cases cover cleanup while Do owns its private-work lock, both reset/END_STREAM
orders, stop and own/foreign Write errors, quiescent waits, invalid input and cancellation
before HPACK encoding. The tunnel fixture checks both thread-creation failures and joining
both tasks. Its post-Do PING case waits for actual Do completion as well as readLoop readiness;
the latter is independently observable and is not a completion signal.

Final isolated verification: `artifacts/lite-client/checks/20261007-083606`.
Focused fetch/cleanup/tunnel suites and fully instrumented fetch/cleanup ASan/UBSan pass.
The full offline gate passes with 7103 `ok` lines (assertions/check summaries, not independent
tests), both architecture/plane builds and QEMU crypto checks. All 316 compiled-source/test
manifest entries match the working tree after verification. Host candidate SHA-256:
`01fe10e7ca9f99ebdc5423750eba5b48d09c68c762f404d2e142a8bc49b77642`.
Earlier attempts are retained separately: one source snapshot was superseded; another fixture
incorrectly expected zero MAX_FRAME_SIZE to be accepted; another assumed readLoop readiness
meant Do completion. Their failure explanations do not convert them into passing gates.

Two private mutants are rejected with a passing control under
`artifacts/lite-client/checks/20261007-082940-1b9cf167/mutations`: removing the pre-encoding abort
check and running split cleanup inline from Write completion. The fetch/main/cleanup source
identities match the final gate; the separate tunnel fixture was corrected afterwards.

Supplemental TSan build succeeds, but the first instrumented test fails before execution:
`FATAL: ThreadSanitizer: unexpected memory mapping`, exit 66, no OOM. The final check directory's
`tsan-receipt.json` records `inconclusive-runner-error`, zero completed tests and `tsan_pass=false`.
Before/after source guards pass. No automatic retry or host ASLR/sysctl change is attempted;
there is no conclusion about races from this failed runtime startup.

A fixed local diagnostic, not acceptance, completes four rounds and 60 bigbody connections
under `artifacts/lite-client/diagnostics/request-tasks-20261007`. It uses the unchanged frozen
stand image, alternating role order, two candidate rounds with two repetitions each and two
old-binary rounds with one each. All source/input guards and executed binary identities pass.
The frozen original parser and an independent wire count agree. Single-repetition stand logs
omit sample labels: frozen context compatibility assigns sample 1, with explicit enforcement
of the same single-preface and first-path invariants. Missing refund observations are retained.

| Diagnostic group | C CANCEL | Reference CANCEL | Descriptive gap |
| --- | --- | --- | --- |
| New split candidate | 14/20 (70%) | 11/20 (55%) | +15 percentage points |
| Old binary | 4/10 (40%) | 1/10 (10%) | +30 percentage points |

These small unequal groups are not comparable acceptance cohorts: reference counts change
markedly across rounds. No CI, improvement, equivalence or causal claim follows. Candidate
per-round first-request medians are 526.5/636 us versus reference 405/361 us, descriptive only.
Reset-before-refund observations remain for both roles (candidate C/reference 7/4, baseline 3/0).
The 136-block failed bigbody experiment's 1022 evidence-manifest entries are rechecked unchanged;
no samples are pooled or reference controls subtracted. G2 remains open.

The 64-session x86 fixture reports 8228 KiB RSS (2720 KiB baseline), 15791 us startup CPU and
21978 us lifecycle CPU. Each of the two tasks reserves 8 MiB of virtual stack, not resident RSS.
Native CPU/RSS/stack and wire acceptance remain unverified. The saved measurement checkpoint is
not replaced: `START-LITECLIENT-MEASURE.cmd` still selects the preceding binary. This diagnostic
does not launch a long experiment, touch routers, deploy or commit anything.

#### Follow-up split trace and independent-readLoop counterexample

This historical counterexample is addressed by the current readLoop checkpoint above;
its original trace/probe evidence remains unchanged and is not a current regression pass.

`artifacts/lite-client/diagnostics/split-trace-20261007` retains a fixed four-round,
40-connection diagnostic of the same new split source: rounds 1/4 traced, 2/3 plain,
both role orders, with no production edit. The private traced build and focused suites
pass; frozen source/input guards and executed identities pass. Ten complete buffers
have zero drops, contiguous sequences and monotonic timestamps. Trace CANCEL counts
match raw wire counts and the frozen parser. Six traces decide CANCEL before DATA;
four decide after END_STREAM and do not reset, including one where Close precedes END.
All ten show readLoop resumption via Do (28 total); no causal or acceptance claim follows.

A separate deterministic public-driver probe holds real private redirect preparation,
feeds PING plus END_STREAM behind an actual request Write and completes that Write.
The independent request task is quiescent and the writer is free, yet read_ready is
false and the accepted frames await Do. Releasing/stepping Do produces the ACK, then
its completion and another Do turn process the buffered END without new input.
Probe exit 0 records this unresolved dependency; it is not an independence pass.
Source guards pass. The intended next correction and regression requirements are
documented in CONCURRENCY.md; this diagnostic does not implement that correction.

The permanent analyzer's control passes and four private log mutations are rejected
under `split-trace-analyzer-checks-20261007-v3`: incomplete controller, dropped trace,
wrong executed binary and sequence gap. The two earlier harness failures are preserved,
not counted as passes. No workload was repeated or original log changed during them.
The 136-block evidence and saved checkpoint stay unchanged, and G2 remains open.

### Approved G2 plan: final cleanup acquisition and owner scope, 2026-10-05

The newer split-driver and independent-readLoop verification are documented above
and in CONCURRENCY.md; the following is historical evidence.

Follow-up source audit found the previous driver's same-stream unfinished request Write
was incorrectly treated as foreign. Go doRequest calls cleanup only after writeRequest
returns (pinned transport.go:1059-1061). cleanup_ready now rejects that stream-local
dependency without reinstating a global writer barrier. The existing three own-request
cases cover successful Flush then two-phase cleanup without new input, stop, and error
before cleanup was entered. Forgotten-DATA now holds a genuinely foreign readLoop PING;
its feed remains held until that readLoop Flush returns, then refunds exactly 4102 bytes
on the connection only. The case count remains 116, not inflated by corrected fixtures.
Focused fetch/cleanup/tunnel pass for this correction. A new fresh full offline gate passes
with 6613 `ok` lines (assertions/check summaries, not independent tests), both HYSTERIA
planes, both router architecture/plane builds and 45 QEMU crypto checks. Fully instrumented
fetch/cleanup ASan/UBSan and three TSan runs pass. The control passes; all nine targeted
mutants fail, including the new own-request guard mutant. Evidence is retained separately
under `build-g2-review/approved-plan-20261004/{self-request-focused-3,self-request-mutation-results,self-request-final}/`.
The two earlier corrected-fixture attempts are retained and are not successful runs.
Snapshot source hashes match before/after all verification stages. These result-documentation
updates are checked separately after the executable is frozen.

| Current verified artifact | SHA-256 |
| --- | --- |
| fetch.c | 21b3286ef085fb4423b173bde3464c40688a0dfd9c9f89cd92e46a5b95d68d52 |
| test_cleanup.c | bf20601e7974a35f78ff2e73fedf22a49b69f74e3b92fd14bbed4bb4944742f6 |
| HYSTERIA=0 host measurement executable | 26deeae57a7314f9978886498fbc30ea66b35c2496304b75e119a3d2c98bc3bf |

The 00:26 experiment was stopped at approximately 00:36 for this code defect, with block 1
complete and block 2 started. No CANCEL outcomes were inspected for the stop decision.
Its logs, frozen inputs and INVALIDATED-CODE.md are retained; no samples may be reused.

The approved scope is code, an isolated offline gate and the local G2 stand. Router paired
wire acceptance/resource budget (B/C), SDK/APK/fortify isolation, G5/G6, deployment and commit
are excluded. SSH availability is not authorization for a production load test. B/C remain
open; no router is accessed in this checkpoint.

#### Earlier verified checkpoint, superseded for current code

A fresh pre-change gate passes with 6010 `ok` lines. The cached derivative of lc-build:local
supplies pinned vendor trees, both cross toolchains and link stubs; the repository is mounted
read-only, its cached/staged/unignored-untracked working files are copied to an isolated tree,
and the gate uses a new build directory with `--network none`. No inherited object is accepted
as a fresh build result. This setup avoids writing build products into the working tree.

Cleanup now separates forgetStreamID from the final cc.wmu/werr acquisition even when the
writer is free. Completion releases the matching owner and records sticky werr on the
producing ClientConn. An already-forgotten stream's terminal final check can complete after
connection failure; this does not resume Do, return saved body bytes or produce output.
donec is completion, not successful transmission. Stop takes precedence. The terminal pass
does not invent cleanup for streams that had not reached removal.

Cleanup's writing readiness is narrowed to its own ClientConn. cc.wmu, bufio and Framer
are local to that connection; queue cuts serialize the shared TLS socket and completion ids
retain the separate owners. Public cross-host redirects establish two real ClientConns for
the regression: local reset can queue behind a foreign PING, but cannot replace/acknowledge
its id or reach the socket first. Non-writing local final cleanup need not wait for that
foreign ClientConn. Request admission, held-input draining and other producer resumptions
remain conservative: this checkpoint does not prove their general interleavings and does
not relax those barriers. The readiness rules in CONCURRENCY.md distinguish tested rules
from that remaining work.

The current driver has 116 cases plus seven local checks, adding 28 cases to the preceding
88-case snapshot: four final-acquisition, three opening-read, seven padded-DATA, eight harvest
and six cross-ClientConn cases. DATA body consumption is exercised through actual Do before
refund completion, not only pipe inspection. Broken-pipe DATA returns body plus padding on
the connection only; reset/error follows its own Flush, with stop/error at both boundaries.
The opening guard already existed: new tests verify an early feed stays held until matching
opening completion, including stop/error and resumption without new input. Pre-refund pipe
publication and flow accounting remain the cc.mu-protected portion of processData; these
tests do not claim every Go instruction-level interleaving inside it is reproduced.

A test-only wrapper counts actual lc_spider_sink_commit calls returning. Plain/gzip complete
pages followed by transport loss commit exactly once; incomplete pages, length/CRC failures
and pre-consumer stop commit zero times. It neither counts randomly selected later paths nor
adds production logging/counters. Sink allocation failure is not injected, so this is not an
allocation-success or new-distinct-path metric. The uninstrumented wire stand's closeafter
paths remain reuse observations, not reference/C harvest-commit counts.

All eight targeted mutants are rejected: merged free-writer final acquisition, omitted
sticky-werr close (local supplementary check), early DATA terminal processing, early broken
DATA error, opening read before Flush, restored global cleanup gating, missing harvest and
double harvest. The unmutated control passes. Initial fixture failures (a uint8_t conversion
warning, an incorrect assumption about the initial seq value, and an extra body-read turn)
are retained separately; none is counted as a successful run or a production defect.

The fresh final offline gate passes with 6620 `ok` lines (unit assertions and check summaries,
not 6620 independent tests), both HYSTERIA program builds, all programs for MIPS/AArch64 in
both planes, and 45 QEMU crypto checks. Focused fetch/cleanup/tunnel also pass in HYSTERIA=0;
HYSTERIA=1 is included in the gate. Fully instrumented fetch and cleanup pass ASan/UBSan and
three TSan runs. Snapshot source hashes match before/after every final stage. Evidence is
under `build-g2-review/approved-plan-20261004/{baseline,focused-1,mutation-results,final}/`.
The directory retains its start date; this final checkpoint finished on October 5.

| Frozen artifact | SHA-256 |
| --- | --- |
| fetch.c | af505ed3347f4d34921d1d0f60aa25796ed6589dee88b3ba3fd1c4af17d8ca39 |
| test_cleanup.c | 65965c5409d8fb6b596d86df2ba26c66c9aa2750956e76e979ccd2066a2ab285 |
| HYSTERIA=0 host measurement executable | f1d68728d00c27d6b475843132a3fdeb44bc470783a4895a30c5115654935232 |

The source-order clock wrapper test remains part of the stand's nine suites. The measuring
destination and its io-return-v2 clock are unchanged. Documentation added after the compiled
snapshot is checked separately; prior native and 800-connection figures belong to their older
sources/binaries, not this new executable.

The next experiment is fixed before any new sampling: 128 interleaved primary blocks,
64 client/reference and 64 identical-Xray control, plus eight separate full-scenario context
blocks. Every block restarts destination, node and both clients. An eight-block ABBA pattern
balances time and order; primary has 32 blocks per client-order stratum/comparison, ten paired
probes per scenario, five retries per probe. bigbody/gzbody/latebig therefore each have 3200
connections per role/comparison. Context uses all 17 scenarios, one pair per scenario/block;
context/control/old samples are neither pooled nor subtracted from the primary comparison.

Analysis is preregistered: 100000 whole-process-block bootstrap replicates, seed 20261005,
resampling within client-order strata, marginal 2.5/97.5 percentiles per scenario. All retries
and probes of each block stay together. These empirical intervals assume within-order block
exchangeability, not scheduler equivalence or simultaneous familywise coverage. Unchanged
criteria require absolute CANCEL point gap <=10 points, interval upper end <=+10, absolute
first-request median gap <=100 us and at least three rounds. No early pass, extension or
replacement of failed blocks; bad counts/clock/hashes invalidate the experiment. The run has
1800-second block and 48-hour overall safety deadlines; neither is production pacing.

The analyzer additionally passes 28 parser/design/bootstrap fixtures, including the old accepted
100-connection block reproduced as 13/16 cancellations without pooling it. A full synthetic
136-block fixture produces exactly 38400 primary and 1360 context connections, zero known
block deltas/intervals and a 100 us median-gap boundary; corrupting the last primary block is
rejected. Synthetic output is marked as such and is not wire evidence. The manifest includes
the frozen plan, analyzer, functions, driver, watcher and all four executed programs; their
actual hashes are rechecked before final analysis, not only trusted from an earlier log.

The experiment started on October 5 at 00:26 MSK in `lc-g2-approved-measure-20261005`.
Evidence is under `build-g2-review/approved-measure-20261005/`; a hidden local watcher records
container state/logs and runs the frozen analyzer only after successful completion. It cannot
rerun blocks, change sources/documents or close G2. Stand race tests pass three times before
sampling; reference, destination, probe and client executables are frozen and hashed before
the first block. The container has a 2 GiB/no-swap memory ceiling and 512-task limit, with no
CPU quota. This is a host safeguard, not a router resource result or production scheduling
change. The previous eight-block duration suggests roughly 19-20 hours for this fixed design;
the 48-hour deadline terminates an overrun as incomplete, not a pass.

That first experiment is now incomplete and invalidated for code as described above. Its
samples are not accepted, pooled or reused. The corrected executable's separately identified
complete experiment started at 00:46 MSK on October 5 in
`lc-g2-measure-self-request-20261005`; evidence is under
`build-g2-review/approved-measure-self-request-20261005/`. Its frozen image is
`aaba252c6b7c28fb9143ba120c7788924719b1198f6344a9f314632a23243c96`.
The same 136-block design, limits and analysis were preregistered before this launch; these
are not replacement blocks in the stopped experiment. That run was subsequently stopped;
its 74 completed blocks remain separate and are not accepted or pooled into later runs. A new
manual run started at 11:12 MSK and stopped after 79 completed blocks with block 80 incomplete.
Its complete-block prefix is exploratory only: bigbody CANCEL is 460/1950 for the reference
and 630/1950 for C, a +8.72 percentage-point gap with a whole-block 95-percent interval of
+6.10 to +11.38. The original +10 upper-bound condition is not established. Final source/input
guards and context blocks are missing; neither acceptance nor runtime equivalence is claimed.
The saved evidence is under the separate `artifacts/lite-client/measurements/` run directories
in the enclosing workspace. Docker images/containers were later removed by the maintainer;
recovery now builds a separately identified checkpoint with image archives outside Docker.
Old evidence, source/binary hashes, design and limits are not rewritten or treated as resumable.
The expected full-run duration remains roughly 19-20 hours, with a 48-hour safety deadline.
Final publication of new measurements requires
all 136 blocks and strict source/binary/group validation. G2 remains open for
cancellation uncertainty and excluded hardware acceptance. No sleep/yield tuning or threshold
relaxation is introduced in production.

The subsequent cleanup pre-writer regression holds Close's actual credit Write while cleanup
chooses CANCEL, then feeds END_STREAM before completing that Write. Go selects the reset before
waiting on `cc.wmu`, so its decision must survive that peer completion. Five cases add stop and
both writer/reset failure paths, no duplicate actions and progress without new input. The old
source fails the reset assertion. The new source passes focused fetch/cleanup/tunnel tests,
ASan/UBSan and a fresh full offline gate (6739 ok lines, both architecture/plane builds and
45 QEMU crypto checks). Earlier TSan/resource/wire results are not acceptance of this new source.
The new immutable binary has SHA-256
`93a97f4c32f11cc7e12e6e2859d175e5937d035f27617bf26f3aace5cd9f8f24`.
Its next wire experiment must be a new full run, started manually; it has not been measured here.

### Concurrent spider: block sensitivity and clock-wrapper mutation, 2026-10-04

A further exploratory analysis keeps the accepted 800-connection experiment unchanged.
The original bootstrap resampled ten paired probe groups within each of four fixed process
blocks. A separate whole-block sensitivity analysis retains each block's fifty connections
per role and enumerates all 256 equally weighted four-draw block-index tuples. CANCEL
counts, timing summaries and the primary acceptance criteria are not recomputed or replaced.
Client/control data remain separate; input paired-probe hashes match before/after.

| Resampling unit | C minus reference range (points) | Control B minus A range (points) |
| --- | --- | --- |
| Paired probes within fixed blocks, original conditional bootstrap | -2 to +16.5 | -8.5 to +6.5 |
| Whole process blocks, exploratory empirical sensitivity | +3.5 to +12 | -5 to +5 |

The point gaps remain +7.5/-1. Whole-block endpoints use ceil(0.025*256) and
ceil(0.975*256), ranks 7/250, on the enumerated sorted sums. Eleven fixtures cover zero,
constant/sign-reversed/shifted counts, exact state count, invalid block/group size,
duplicate probe identities and inconsistent/out-of-range cancellations. Evidence and
scripts are in `build-g2-review/fixed-bigbody-20261004/block-sensitivity/`.
Only four process blocks per comparison are observed: these empirical endpoints do not
establish population coverage, block exchangeability or equivalence. They are not a
replacement confidence gate. Both C ranges cross +10; choosing the narrower one cannot
close G2. Any future fixed experiment must address independently restarted process blocks
and order balance, not simply label retries as independent or extend a sample until it passes.

The clock tests also gain an explicit source-order invariant for capture.Read/Write.
Go AST inspection requires that the conditional timestamp immediately follow underlying
I/O (only a zero-initialized local time.Time may intervene), precede capture.mu.Lock,
and be passed to note after the lock. This policy assertion supplements runtime capture
tests; it is not a general control-flow proof or an injected clock hook in the measuring
server. All nine stand suites pass three times under the race detector offline.
A mutation moving time.Now behind capture.mu.Lock still passes the previous eight suites
but fails the new Read and Write subtests. It is retained separately and never measured.
Evidence, test snapshot and source hashes are in `build-g2-review/block-clock-audit-20261004/`.

Destination main.go remains identical to the fixed experiment's frozen source manifest:
`f3805fd29c8913f69e216c0379a3bbaebeeafca5e3f3187344428d5e6b7b2b1a`.
Only its test changes, to SHA-256
`4a81b95406474d63afaecf6b525b5e1234105626d659b4a57f1c093ad17a5f8a`.
No new wire sample, C offline gate or native run is claimed for this audit. Production C
and the measured executable remain unchanged, and no router is accessed during this audit.

### Concurrent spider: extended driver native on MT7621, 2026-10-04

The extended test-fetch-cleanup now passes natively on the non-production MT7621:
all 88 public-driver cases, including the ten late-DATA-after-redirect cases, plus the six
supplementary owner checks. This is the HYSTERIA=0 fixture, not an installed client or paired
wire acceptance. Production sources and test_cleanup.c are unchanged from the preceding
offline/sanitizer snapshot. Native fixture SHA-256 is
`c1b804fe0d091853640150413ba9cef393fc92d605896cb2b64db8496855805a`;
local/copied/executed/post-run hashes match. The ELF is 32-bit little-endian MIPS soft-float
and links the router's real libmbedcrypto.so.16 and libz.so.1; the build-time link stubs
are not uploaded or executed.

The preflight requires at least 32768 KiB MemAvailable. A low-priority watchdog polls every
20 ms, stops at RSS over 8192 KiB, MemAvailable below 16384 KiB or 15 seconds, and records
wait4 peak RSS/CPU. Kernel limits separately cap CPU at ten seconds and virtual address
space at 320 MiB because the paths arena reserves 256 MiB with MAP_NORESERVE. The watchdog
is sampled protection, not a hard RSS limit or protocol pacing. The successful run reports
1180 KiB peak RSS, 154019 us CPU, limited=0 and stopped=0. Its fixture is 329780 bytes and
the guard 6180 bytes. No ports, installed binaries, services or persistent settings are touched.

Logs, board data, guard/runner sources and hashes are retained in
`build-g2-review/late-native-20261004/`. The owned temporary directory was removed after
download and local verification; the local artifacts can reproduce the fixture. AX3000T
was not accessed during this run. These resource numbers concern the unit fixture only,
not the Go reference, a deployed tunnel, session scaling or scheduler equivalence.

The full pinned MIPS Xray was already built with -s -w. ELF inspection finds no DWARF debug
or ELF .symtab section to remove for a substantial saving. Applying strip --strip-all to an isolated copy
changes 35979455 bytes to 35919508 bytes, saving only 59947 bytes. The original remains
unchanged; the inspection copy was neither executed nor uploaded and is not an accepted
reference replacement. Even its file alone consumes almost the available RAM on the lab
board's RAM-backed /tmp before runtime allocations. Removing reference modules or runtime
metadata is not used to fit the test. Paired native wire acceptance remains pending.

### Concurrent spider: late DATA across redirect and phase diagnosis, 2026-10-04

An exploratory post-measurement diagnosis keeps all 800 connections from the fixed bigbody
experiment below. It matches block/role/probe/CANCEL identities and first-request clocks to
the accepted CSV, then extracts exact frame tags, including coalesced tags, at I/O return.
Missing END_STREAM is a category, not grounds for dropping a connection. Six connections
lack an observed response END_STREAM; all six carry CANCEL. All 800 show 5000 DATA payload
bytes. Input hashes match before/after. This diagnosis does not change the primary sample,
bootstrap, thresholds, stop rule or acceptance result.

| Role (200 connections each) | CANCEL without observed END_STREAM | CANCEL before observed END write-return | CANCEL after observed END write-return | Connection credit after redirect HEADERS on client wire |
| --- | --- | --- | --- | --- |
| Reference in C comparison | 1 | 0 | 53 | 14 |
| C | 2 | 1 | 66 | 9 |
| Control reference A | 1 | 0 | 43 | 15 |
| Control reference B | 2 | 1 | 39 | 14 |

There are no equal-time CANCEL/END observations and no CANCEL after the new HEADERS on
client wire. Body-to-END write-return medians (observed END only) are 42/45 us for reference/C
and 44/45 us for control A/B. END-to-CANCEL medians (CANCEL with observed END only) are
166/185 us and 179/182.5 us. Missing END and late credit are observed in both C and reference,
not C-only findings. Neither these conditional medians nor a destination Write's completion
establish when the client readLoop processed END_STREAM. A client can have read bytes before
the server's Write returns; cross-direction timestamp order is not causal byte order. No new
production defect or reason to add scheduler pacing is established by this diagnosis.

The phase parser has 15 synthetic fixtures: coalesced tags, cross-direction ordering,
equal timestamps, missing DATA/END/credit, combined DATA+END, late credit, reset order,
duplicate payload, missing redirect, mismatched reset count and out-of-order server writes.
An initial parser assumed every response had a separate empty END frame and every refund
preceded the redirect. Actual captures refuted those assumptions; the diagnostic now
classifies those observations explicitly rather than discarding them. Raw logs, input hashes,
connection/summary CSVs and parser/test scripts are retained in
`build-g2-review/fixed-bigbody-20261004/cancel-phase-diagnostic/`.

Ten new production-driver cases cover the whole path: Close before DATA, actual CANCEL
completion, stream 3's request Write in flight, late 5000-byte DATA for forgotten stream 1,
and exactly one connection-only refund after the request Flush. END_STREAM is present or
absent, with normal completion and stop/error before and during the refund Flush. Repeated
steps neither duplicate credit/reset nor mutate the old/new stream. There are now 88 public
driver cases plus six supplementary owner checks. Both HYSTERIA=0/1 fixtures, fully linked
fetch-driver ASan/UBSan and three TSan runs pass. A mutation dropping old-stream DATA only
after stream 3 is allocated fails the new accounting assertion; earlier forgotten-stream
cases alone do not detect that narrower mutation. The initial fixture incorrectly expected
Write-blocked status after no Write remained; it was corrected to assert repeated no-output
and unchanged accounting. That initial failure is retained separately, not counted as a pass.

Evidence is in `build-g2-review/late-redirect-20261004/verified/`. Only the test changed:
test_cleanup.c SHA-256 is `7329e755530bbff3cf3b40af3005fe3fc3c361bb96668ff8414ae7b79f8eef06`.
Production fetch.c and the previously measured executable retain the hashes below; no new
wire sample is claimed for this test-only update. The native follow-up above runs the
extended fixture; it does not replace the pending paired native wire comparison.

A fresh `build-late-gate` full offline gate also passes with the 88-case fixture: host
tests/reference checks, both HYSTERIA builds, every MIPS/AArch64 program in both planes,
and all 45 ARM64/QEMU crypto checks. The initial run failed because the measuring image
kept toolchains/link stubs in /w/dl, not this snapshot's dl. Only those cached dependencies
were copied into the isolated snapshot; source hashes match before resume and after the
complete repeated `make check`. No gate target or criterion was disabled. Initial and
resumed logs are retained separately. The build directory began empty; report edits after
the source freeze are not claimed to be part of that compiled snapshot.

A read-only resource recheck still does not admit the paired native workload: the lab
MT7621 has 37396 KiB MemAvailable, no swap and 1812 KiB free overlay. Its /tmp is RAM-backed;
the pinned full MIPS reference alone occupies 35979455 bytes before runtime allocations.
The production AX3000T has 52528 KiB MemAvailable and no swap; no test processes, uploads,
services or configuration changes were made there. Explicit authorization does not replace
a safe resource preflight. Paired native wire acceptance remains pending.

### Concurrent spider: fixed larger bigbody experiment, 2026-10-04

Following the small-sample identical-reference rejection below, a larger experiment was
fixed before sampling: 200 connections per role for the C/reference comparison, plus 200
per role for the identical-Xray control, 800 in total. Each comparison has four fresh-process
blocks, ten paired probes per block, and five retry connections per probe/role. There are
eight blocks, with comparison kinds interleaved C/control/C/control/control/C/control/C.
C block order is ref/lc, lc/ref, lc/ref, ref/lc; control order is the inverse. Both kinds and
both first-role orders are balanced in time. Probes remain sequential and preserve the
existing six-second settling interval; this is not a higher-concurrency workload.

The stop rule is all eight blocks, regardless of intermediate results. Missing/extra samples,
wrong clock versions, malformed captures or hash mismatches reject the experiment; no failed
block is silently replaced. The CANCEL point-gap limit remains 10 percentage points and
the first-request median limit 100 us. Old observations and control observations cannot be
pooled with C observations to obtain a pass. This is a focused bigbody experiment, not a
new all-scenario or hardware acceptance gate.

SAMPLE_REPEATS (1-20, default 1) and an optional scenario-file probe number support the
larger run. Destination logs preserve that number without changing HTTP/TLS responses or
the io-return-v2 clock. Eight stand suites pass three times under the Go race detector,
including old/new scenario syntax, invalid numbers, and decoded sample/clock preservation.
The C sources and executable remain the previously validated immutable snapshot.

Uncertainty analysis retains all five retries as one probe group. It resamples paired
role-A/role-B probe groups within each of the four blocks, ten groups per block, using
100000 seeded replicates and the 2.5/97.5 percentile endpoints. This exploratory interval
is conditional on the four process blocks; exchangeability within blocks is an assumption,
not proof of independence, population equivalence or Go scheduler fidelity. The seed is
20261004; PowerShell/CLR versions are recorded. Signed gaps are role B minus role A. Control
gaps are not subtracted from C gaps and bootstrap endpoints do not replace the point gate.

The frozen plan, driver, analysis script, manifests and raw logs are retained in
`build-g2-review/fixed-bigbody-20261004/`. Plan/driver/client/adapter hashes are checked
before every block and after measurement; the analysis script was also copied and hashed
before the first block completed. Full source manifests are checked before/after. Source
fetch.c is still `25b10217d0199f418c87e6a337cd8b2e6d2ddc23dbf4c780c2060bd25fa8ee36`;
the client executable is `a21b10bbfd1179f6616e9d92ed26ffd52d84427d44fbc332c06a3585524c0748`.
No router processes, installed clients, services or configuration are changed by this run.

All eight blocks completed successfully with exactly 800 valid connections, five per
role/probe/block, the expected clock and no frame-parse errors. Frozen input and full source
manifests match after measurement. The executed C copy matches the immutable hash in every
C block. All eight reference binaries and all four reference-B launch hashes match Xray
`1311f87606134f536326b4e8e62b96d49d279aebb12773b8546ecbf119e079e2`.

| Comparison | CANCEL A / B (out of 200 each) | Median first request A / B (us) | p95 A / B (us) | Signed CANCEL gap (points) | Conditional bootstrap interval (points) |
| --- | --- | --- | --- | --- | --- |
| Reference / C | 54 / 69 | 314.5 / 286.5 | 521 / 738 | +7.5 | -2 to +16.5 |
| Reference A / reference B | 44 / 42 | 324 / 328.5 | 577 / 691 | -1 | -8.5 to +6.5 |

Both comparisons pass the unchanged point criteria: absolute CANCEL gaps are 7.5 and
1 point, and median gaps 28 and 4.5 us. The conditional C interval crosses the +10-point
limit; the experiment therefore does not establish cancellation equivalence or rule out
a larger underlying gap. This interval was exploratory, not a newly substituted acceptance
criterion. The reference control is a separate negative control, not a correction to C.
Per-block C/reference CANCEL counts are ref/lc 13/16, 17/18, 16/23, 8/12 (50 each);
control A/B counts are 10/9, 11/9, 9/13, 14/11. Nearest-rank p95 uses rank 190.
The recorded analyzer runtime is PowerShell 5.1.26100.9444 / CLR 4.0.30319.42000.

Connections, paired probes, summaries and the analysis are retained beside the raw logs.
Earlier small-sample failures remain reported below; none were discarded or pooled into
this larger sample. This is a new focused stand result with eight race-tested stand suites,
not another full C offline gate. G2 remains open for uncertainty about cancellation and
paired native wire acceptance. No scheduler pacing, artificial delay or production-code
adjustment was introduced to obtain this result.

### Concurrent spider: I/O clock boundary and counterbalanced stand, 2026-10-04

The preceding 240-connection sample was additionally split into opening and first-HEADERS
phases. In closeafter, opening medians are ref 317 / lc 202.5 us, first HEADERS 389 / 258 us,
and within-connection opening-to-HEADERS medians 59.5 / 37.5 us. These are separate medians,
not an additive decomposition. Much of the observed difference is already present before
response processing; the first-request metric alone does not justify changing Body.Close.
Path-stratified observations also differ, but a draw of `/` is not necessarily the first
connection: it remains in the harvested path set. These observations do not establish cause.

The stand had another measurement-boundary defect: capture.note took the timestamp only
after waiting for capture.mu, copying bytes and parsing/formatting frame tags. Read/Write
now save the timestamp immediately after underlying I/O returns and before capture locking.
Each connection marks `clock=io-return-v2`; `capture+` reports observation overhead separately.
This is plaintext I/O return at the destination, not packet-arrival time or a measurement
of the client scheduler alone. Non-timing runs do not acquire an extra clock timestamp.

Six capture test suites, including read/write clock subtests, pass three times under the
Go race detector offline. They cover known completion timestamps, split preface/frames,
bytes returned alongside EOF, partial failed Write without observing an unwritten END_STREAM,
disabled timing and concurrent capture. A mutation restoring observation-time timestamps
fails the read and write boundary assertions. A first standalone test invocation lacked
generated go.sum entries; offline go mod tidy from pinned cached dependencies corrected the
test setup. It did not require a source/library change or network download.

The stand also accepts the two validated CLIENT_ORDER permutations; invalid values fail
before setup or process startup. Four paired rounds were fixed before sampling in ABBA order:
ref/lc, lc/ref, lc/ref, ref/lc, for all four scenarios. The original criteria remain unchanged;
no round selection or production scheduling delay is used. New-clock samples are kept
separate from the preceding observation-clock sample, not pooled to improve an outcome.

Evidence is in `build-g2-review/io-clock-snapshot/`. The measuring container first validates
the preceding source manifest, updates only stand main.go/main_test.go/run.sh, then records
a new full manifest. The validated C sources and executable are unchanged: fetch.c SHA-256
`25b10217d0199f418c87e6a337cd8b2e6d2ddc23dbf4c780c2060bd25fa8ee36`,
lc-tunnel SHA-256 `a21b10bbfd1179f6616e9d92ed26ffd52d84427d44fbc332c06a3585524c0748`.
The prior C offline gate, sanitizer and native lifecycle results apply to these same C bytes;
this clock correction is validated by the separate stand tests, not claimed as a new full
offline C gate. No new router processes or configuration changes were made.

All four ABBA rounds completed with exactly 160 valid connections, five in each of 32
client/scenario/round groups, and io-return-v2 on every valid connection. Full source
manifests match before/after, and all executed/post-run client hashes match the immutable
executable above. Raw logs, strict-parser CSVs and first-request phase CSVs are retained
under the evidence directory's `measure/`.

| Scenario | CANCEL ref / lc (out of 20 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 3 / 7 | 361 / 331 | 511 / 761 |
| gzbody | 0 / 0 | 411 / 337.5 | 599 / 675 |
| latebig | 20 / 20 | 307 / 258 | 458 / 718 |
| closeafter | 0 / 0 | 320 / 280.5 | 607 / 683 |

Median gaps are 30/73.5/49/39.5 us, within 100 in this sample. Bigbody's 20-point CANCEL
gap fails the unchanged 10-point criterion; per-round ref/lc counts are 0/2, 1/2, 1/2, 1/1.
Closeafter path draws are 14/20 vs 16/20, not commits. Nearest-rank p95 of 20 uses rank 19.
First-HEADERS capture-overhead medians are 0-1 us in all groups; the clock correction is
real, but those overhead observations do not explain the old 131 us difference. The order
control, independent new sample and changed clock are not evidence of a causal fix to
client scheduling. G2 remains open for CANCEL variability and hardware wire acceptance.

An additional control experiment was fixed in advance: four ABBA rounds of Xray against
another instance of the exact same Xray executable. Role B uses an adapter that changes
only its local inbound port from 19990 to 19991 in role A's generated laboratory config,
then execs the same reference file. Raw role `lc` in this experiment means reference B,
not lite-client; its summary parser explicitly relabels the roles refA/refB. Evidence is
kept separately in `build-g2-review/io-clock-reference-control/`. This calibrates natural
variation in the criteria; it cannot count as C-client acceptance or relax the thresholds.

The control completed with another 160 valid connections, matching source manifests and
io-return-v2 on every valid connection. Both roles use Xray SHA-256
`1311f87606134f536326b4e8e62b96d49d279aebb12773b8546ecbf119e079e2`;
role B's launch hash and the reference post-run hash match in all four rounds. The adapter
hash is recorded separately and is not an executed C-client hash.

| Scenario | CANCEL refA / refB (out of 20 each) | Median first request refA / refB (us) | p95 refA / refB (us) |
| --- | --- | --- | --- |
| bigbody | 5 / 2 | 324.5 / 302.5 | 703 / 611 |
| gzbody | 2 / 0 | 329 / 336 | 653 / 413 |
| latebig | 20 / 20 | 340 / 340 | 434 / 890 |
| closeafter | 0 / 0 | 310.5 / 294 | 648 / 438 |

Bigbody's 15-point gap fails the same 10-point criterion on the unchanged reference itself.
Gzbody is exactly at 10 points; median gaps 22/7/0/16.5 us pass. This demonstrates that a
20-per-role point-estimate gate can reject identical reference code under this workload.
It does not prove that lite-client has the same distribution, or explain its 20-point gap.
The control gap must not be subtracted from the client's gap, nor may the two experiments
be pooled to obtain a pass. G2 remains open: the next cancellation comparison needs an
adequately sized fixed sample and explicit uncertainty/control analysis, alongside the
still-pending paired hardware wire acceptance. No criterion has been relaxed or marked
passed on the strength of this control.

### Concurrent spider: independent Close handoff and private Do work, 2026-10-04

The completion driver no longer runs doRequest cleanup inline on Body.Close's stack.
Close breaks/aborts/accounts and yields; a subsequent step makes the reset decision.
END_STREAM received between those phases can suppress CANCEL, whereas an already selected
reset remains owned until completion. Eight new public-driver cases cover both orderings,
unread credit, stop/error and resumption without fresh input. Restoring inline cleanup fails
the handoff assertion. The synchronous non-barrier driver retains its existing behavior.

Redirect URL/header preparation now releases the protocol mutex while holding a separate
sole-consumer guard. Three concurrent cases pause that private work and drive DATA/END_STREAM
and completion, stop, or Write failure from another thread. They assert that the protocol
mutex is free and the consumer guard remains held; resumption rechecks stop/failure before
publishing state. A mutation holding the protocol mutex fails this boundary assertion.
There are 78 public-driver cases plus six supplementary owner checks in test-fetch-cleanup.
No timer, sleep, scheduling priority change or fixed delay was added to production.

A fresh isolated copy, seeded only with vendor/dl dependencies and no old build objects,
passes offline `make -j4 BUILD=build-private-do check`: both HYSTERIA planes, MIPS/AArch64
builds, consistency checks and 45 AArch64 crypto checks under QEMU. ASan/UBSan with leak
detection passes fetch and driver; three TSan runs of each pass. Unlike the preceding
checkpoint, every linked C object in these tests is instrumented. This is not full-tunnel
sanitizer coverage or proof that no UAF/race exists. At -O1, existing x509go.c sign-conversion
warnings required `-Wno-error=sign-conversion` in addition to the existing conversion-warning
profile; warnings remain visible and production compiler flags are unchanged.

Evidence is in `build-g2-review/private-do-snapshot/`. Source manifests match before/after
the gate, sanitizers and cross-build. fetch.c SHA-256:
`25b10217d0199f418c87e6a337cd8b2e6d2ddc23dbf4c780c2060bd25fa8ee36`.
The immutable HYSTERIA=0 host executable has SHA-256
`a21b10bbfd1179f6616e9d92ed26ffd52d84427d44fbc332c06a3585524c0748`.
Its compiled source copy is retained in lc-g2-private-do-gate-20261004 and the sanitizer
resume container; later report edits do not change this compiled snapshot.

Native test-fetch-cleanup and test-spider-tunnel also pass on the non-production MT7621
(Mi Router 4A Gigabit, OpenWrt 25.12.5, kernel 6.12.94). Local/copied/executed/post-run SHA-256
hashes match for each fixture. The tunnel test includes the actual session/worker handoff:
64 simultaneous workers use 3708 KiB RSS against a 1392 KiB baseline; after all joins/reaping,
RSS is 1396 KiB. Reported per-worker stack reservation is 134532 bytes; startup/lifecycle
CPU samples are 43903/64426 us. These are native lifecycle/resource fixtures, not paired
wire measurements or a deployed client. The test-only harness caps actual RSS at 24 MiB,
runtime at 45 seconds and uses a separate 320 MiB virtual-address limit because the paths
arena reserves 256 MiB with MAP_NORESERVE. An initial 24 MiB address-space cap failed allocation;
it is retained as a harness failure, not counted as a product test failure or acceptance run.
No installed binaries, services or configuration were changed; AX3000T was read-only.
The owned temporary test directory was removed after all logs were copied locally.
The separate cross-built MIPS lc-tunnel artifact has SHA-256
`076e5273a5584a990c6c8558d4f23c33e3e179d7757372e8e5eea33cf65eb670`;
it was explicitly relinked after the source update, not reused from the seed image, and
has not been uploaded or executed as a client. Fixture execution is recorded separately.

Hardware wire acceptance remains pending: the full pinned MIPS Xray is 35979455 bytes and
the probe 5177537 bytes; /tmp is RAM-backed, available RAM is roughly 34-37 MiB and the overlay
has only about 1.8 MiB free. Uploading/running the paired reference there is not a safe test.
An adequately sized non-production target or explicit bounded AX3000T authorization is
required. Host/QEMU and native lifecycle results do not substitute for this gate.

Three new paired offline rounds on the immutable host binary above contain exactly 120
valid connections (five per client/scenario/round). Source hashes match before/after, as do
the snapshot, all three executed copies and the post-run snapshot. No other owned build or
trace job ran during sampling. Raw logs, hashes and strict-parser CSVs are in
`build-g2-review/private-do-snapshot/measure/`.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 5 / 6 | 317 / 344 | 1028 / 796 |
| gzbody | 0 / 0 | 312 / 357 | 662 / 883 |
| latebig | 15 / 15 | 287 / 286 | 369 / 993 |
| closeafter | 0 / 0 | 430 / 283 | 977 / 739 |

Bigbody's CANCEL gap is 6.7 percentage points, below 10; per-round ref/lc counts are
2/3, 1/1, 2/2. Median gaps are 27/45/1/147 us: closeafter exceeds the 100 us criterion.
Harvested-path draws in closeafter are 12/15 vs 11/15, not commits. Nearest-rank p95 with
15 samples is the maximum. This sample does not close G2 or establish causality/statistical
equivalence. Before further sampling, three additional paired rounds on this same binary
were fixed in advance; the original failed timing sample remains separately reported
and all six rounds are included in the combined analysis, without selecting rounds.

The additional fixed three rounds completed on the same immutable executable, again with
120 valid connections and matching executed/post-run hashes. The retained isolated source
was reused without copying the later documentation edits; its manifest still matches before
and after. Separate logs/CSVs are in `measure-second/`; strict-parser combined logs/CSVs are
in `measure-all-six/`, with exactly 240 valid connections and five samples in each of 48
round/client/scenario groups. The second set alone has bigbody CANCEL 6/15 vs 8/15 (13.3
points, above 10), and median gaps 20/72/36/86 us. Neither set is hidden by the aggregate.

| Scenario | CANCEL ref / lc (out of 30 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 11 / 14 | 318 / 321 | 623 / 759 |
| gzbody | 0 / 0 | 294.5 / 350.5 | 460 / 741 |
| latebig | 30 / 30 | 283.5 / 310.5 | 601 / 818 |
| closeafter | 0 / 0 | 389 / 258 | 876 / 739 |

Across all six rounds bigbody's CANCEL gap is exactly the allowed 10 percentage points;
median gaps are 3/56/27/131 us. Closeafter still fails the 100 us host timing criterion.
Even-sample medians average the two middle values; nearest-rank p95 of 30 uses rank 29,
not the maximum. Harvested-path draws are 22/30 vs 21/30, not commit counts. These samples
do not prove statistical equivalence or causality. G2 remains open for the residual host
timing discrepancy and paired hardware wire acceptance; no scheduling-delay adjustment
was made to fit the timing threshold.

### Concurrent spider: Read and writing-cleanup completion, 2026-10-04

The body consumer now reads/accounts behind request and cleanup Writes, as well as readLoop
Writes. Only a credited Read's own writer/Flush wait blocks its saved result; independent
reads without credit can continue. Writing cleanup now publishes its pipe error after the
reset's actual successful Flush completion, before forgetting the stream and the final
writer/donec check, as cleanupWriteRequest/writeStreamReset do in the pinned transport.
That completion wakes a Read which drained the pipe while waiting for the reset, without
requiring another input frame. Writer IDs and whole-Write ownership remain preserved.

The 32 added public-driver Read cases cover request/production cleanup owners, plain/gzip,
with/without credit, stop/error on both waits, exact owned bytes/credit, preserved foreign
Write identity, blocking readiness and no-new-input completion. There are 67 public-driver
cases plus six supplementary owner checks in test-fetch-cleanup. During final source review,
an intermediate cleanup-owner expectation was found to depend on premature pipe error.
It was corrected: before reset Flush the pipe can be drained but its error is not available;
matching completion publishes the error and wakes the waiting Read. The preceding Read-only
code and a mutation restoring early pipe_close both fail the corrected reset-Flush assertion.
The saved-Read/own-Flush mutation was repeated on this final source and also fails the
owned-byte/Flush assertion. That additional mutation check ran after timing samples were
complete, not concurrently with measurement.
Focused driver/fetch/tunnel suites pass with the corrected phases.

A second fresh isolated source copy, seeded only with vendor/dl dependencies and no old objects,
passes offline `make -j4 BUILD=build-read-completion check`: both HYSTERIA planes, MIPS/AArch64
builds, consistency checks and 45 AArch64 crypto checks under QEMU. ASan/UBSan with leak
detection passes fetch and driver; three TSan fetch runs pass. The sanitizer conversion-warning
profile and partial driver instrumentation limits below still apply, not full-tunnel coverage
or proof that no UAF/race exists. These results do not transfer from the intermediate binary.

Evidence is in `build-g2-review/read-completion-snapshot/`. Source manifests match before/after
the gate. fetch.c SHA-256:
`2977b7d931eaf7e5790f4ca0c129bb81d72f091725272f4dcff8c8b3a550437f`.
The HYSTERIA=0 executable prepared after validation has SHA-256
`697fa557b0daf1f33b671c8909a85f0ba23a027d2a790a047635bc2e90bcd713`.
The compiled source copy is retained in lc-g2-read-completion-gate-20261004;
subsequent report updates do not alter it.

Three new paired rounds completed offline (`--network none`) after validation, using the
pinned caches in lc-build:g2-spiderredir-cached. The raw-log parser requires exactly 120
connections and five valid timing samples in each of 24 client/scenario/round groups.
The source copy in lc-g2-read-completion-measure-20261004 matches the gate's manifest before
and after measurement. Snapshot, post-run snapshot and all three executed-copy hashes match
the executable above. No lite-client rebuild occurs in the rounds. Raw logs, hashes,
connections.csv and summary.csv are in `build-g2-review/read-completion-snapshot/measure/`.
The intermediate Read-only samples below are not included in these numbers.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 2 / 10 | 324 / 326 | 648 / 854 |
| gzbody | 0 / 0 | 314 / 338 | 484 / 657 |
| latebig | 15 / 15 | 310 / 288 | 593 / 673 |
| closeafter | 0 / 0 | 305 / 261 | 371 / 741 |

Absolute median gaps are 2/24/22/44 us and satisfy the 100 us host criterion in this sample.
Bigbody's 53.3 percentage-point CANCEL gap fails the 10-point criterion; per-round ref/lc
counts are 1/4, 0/4, 1/2. Closeafter harvested-path draws are 11/15 vs 12/15, not commit
counts. Nearest-rank p95 with 15 samples is the observed maximum. These variable samples
do not establish statistical equivalence or causally explain the cancellation gap. G2 remains
open; producer queue gating and input/consumer interleaving still need investigation, as do
hardware lifecycle/resource measurements. No fixed scheduling delays were introduced.

### Concurrent spider: independent body Read, 2026-10-04 (intermediate, superseded)

This experiment retained premature writing-cleanup pipe error from the preceding code.
Its cleanup-owner Read terminal expectation is not reference-valid evidence; the checkpoint
above corrects both the phase and the test. Its old logs and separate binary are preserved
for provenance, not combined with the final checkpoint's samples or validation results.

The body consumer now runs pipe.Read and flow accounting behind request/cleanup Writes as
well as readLoop Writes. This follows transportResponseBody.Read at transport.go:2173-2223:
cc.wmu is needed only when flow credit must be sent. A Read without credit returns normally;
a credited Read retains its owned bytes until the writer and its actual Flush complete.
Already-returned EOF/error can advance Do behind a foreign writer; Close keeps its own phases.
Production changes are confined to consumer readiness, not writer phases or completion IDs.

`test-fetch-cleanup` adds 32 public-driver Read cases (67 driver cases total, plus six local
owner checks): request and production cleanup-reset Writes, plain/gzip, with/without credit,
stop/error on both waits, exact saved bytes and credit, unchanged foreign Write identity,
blocking readiness, and resumption without new input or duplicate WINDOW_UPDATEs. A local
cleanup reset is induced through an invalid header block, not manual owner mutation. The
initial regression fails against the preceding code at Read's pipe-end continuation behind
a request Write. A mutation returning saved bytes before the actual Read Flush fails the
owned-byte/Flush check. Focused driver/fetch/tunnel suites pass after the readiness fix.

A fresh isolated source manifest, seeded only with vendor/dl dependencies and no prior objects,
passes offline `make -j4 BUILD=build-read check`: both HYSTERIA planes, MIPS/AArch64 builds,
consistency checks and 45 AArch64 crypto checks under QEMU. ASan/UBSan with leak detection
passes fetch and driver; three TSan fetch runs pass. The conversion-warning sanitizer profile
and partial driver instrumentation limits described below still apply; this is not full-tunnel
sanitizer coverage or proof that no race/UAF exists.

Evidence and manifests are under `build-g2-review/read-snapshot/`. Source checksums match
before/after the gate. fetch.c SHA-256:
`269853f01bb5fad7874e34cc72f941e1a875d7811b2ab242c553db584c2ca738`.
The single HYSTERIA=0 executable prepared after validation has SHA-256
`256463df0a1475151c5b79851788c651e698a0299faca6e59000861847a6bf66`.
Report updates do not alter the isolated compiled-source copy retained in the named
lc-g2-read-gate-20261004 container.

Three paired rounds ran after validation with `--network none`, using pinned module/build caches
from the preceding stand retained in `lc-build:g2-spiderredir-cached`. The source copy in
lc-g2-read-measure-20261004 is checked against the gate's manifest before and after measurement;
snapshot, post-run snapshot and all three executed-copy hashes match the executable above.
Lite-client is not rebuilt in the rounds. The raw-log parser accepts exactly 120 connections,
five with valid timing in each of the 24 client/scenario/round groups. Raw logs, connections.csv,
summary.csv and hashes are in `build-g2-review/read-snapshot/measure/`.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 2 / 11 | 407 / 330 | 1033 / 784 |
| gzbody | 1 / 0 | 356 / 366 | 692 / 875 |
| latebig | 15 / 15 | 328 / 326 | 656 / 776 |
| closeafter | 0 / 0 | 365 / 238 | 496 / 873 |

Bigbody CANCEL differs by 60 percentage points, failing the 10-point criterion; per-round
ref/lc counts are 1/5, 0/2, 1/4. Absolute median gaps are 77/10/2/127 us, so closeafter fails
the 100 us criterion. Closeafter harvested-path draws are 10/15 vs 9/15, not commit counts.
Nearest-rank p95 with 15 samples is the observed maximum. This checkpoint does not show wire
equivalence or establish that Read readiness caused the changed cancellation counts. G2 remains
open: the independent Read boundary is tested, producer queue gating and interleaving differences
still need investigation. No fixed scheduling delays were added.

### Concurrent spider: Body.Close phases, 2026-10-04 (preceding checkpoint)

Body.Close now breaks/drops its pipe, aborts the stream and accounts unread connection bytes
before waiting for cc.wmu, as the pinned transport does at transport.go:2227-2263. Its saved
credit phase waits for the writer even when the unread bytes are below the WINDOW_UPDATE
threshold. `close_writer` owns the actual Flush until its matching successful completion;
protocol ACKs and cleanup's final writer check respect it. The redirect waits for both Close's
Flush and cleanup's donec. Response handling is independently ready behind request as well
as readLoop Writes. Body-read/request producer gating remains conservative.

`test-fetch-cleanup` adds 22 public-driver Close scenarios (35 driver cases total, plus six
supplementary owner checks): both writer owners, 0/1/5000 unread bytes, stop/error before writer
acquisition and during credit Flush, late PING input, exact once-only credit/reset and progress
without new input. The initial regression fails against the preceding implementation at the
pre-writer break/abort/account boundary. A mutation omitting close_writer fails the late-PING
check. Focused driver/fetch/tunnel suites pass after the fix.

A new isolated tracked/unignored source copy, seeded only with vendor/dl dependencies and
no previous objects, passes offline `make -j4 BUILD=build-close check`: both HYSTERIA planes,
MIPS/AArch64 builds, consistency checks and 45 AArch64 crypto checks under QEMU. ASan/UBSan
with leak detection passes fetch and driver; three TSan fetch runs pass. The sanitizer
conversion-warning profile and partial driver instrumentation limits described below still
apply. These are boundary regressions, not proof of scheduler equivalence or the absence of races.

Evidence is in `build-g2-review/close-snapshot/`; source checksums match before/after the gate.
The fetch.c SHA-256 is `82a2c8368e4d62350e9fb98218a4aac6308c2e63d6c6264af78c8141ec76d777`.
The HYSTERIA=0 executable prepared there after validation has SHA-256
`85a4b343a69374cac8c7b4e097f1b4010c202fd6800590936967f01f77253e3b`.
Later report updates are not edits to that isolated compiled-source checkpoint.

Three paired rounds completed after validation, with five connections/client/scenario/round:
120 total, 15/client/scenario. The raw-log parser requires exactly five valid timing samples
in all 24 groups. Snapshot, post-run snapshot and all three executed-copy hashes match the
executable hash above; source manifests also match before/after measurement. Raw logs,
connections.csv and summary.csv are in `build-g2-review/close-snapshot/measure/`.
The first stand attempt stopped before samples because a seed symlink was placed inside the
already-existing vendor directory. Its log is retained as initial-seed-layout-failure.log.
The retry corrected dependency placement without rebuilding lite-client, using the same
verified source copy retained in `lc-build:g2-close-source`. The stand had module-download
access; only the validation gate is claimed offline.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 3 / 7 | 524 / 452 | 1116 / 1060 |
| gzbody | 1 / 0 | 428 / 513 | 867 / 1429 |
| latebig | 15 / 15 | 503 / 373 | 2619 / 818 |
| closeafter | 0 / 0 | 401 / 346 | 1126 / 1126 |

Bigbody's 26.7 percentage-point CANCEL gap still fails the 10-point criterion; per-round
ref/lc counts are 1/4, 2/2, 0/1. Absolute median gaps are 72/85/130/55 us, so latebig fails
the 100 us criterion in this checkpoint. Closeafter harvested-path draws are 12/15 in both,
not commit counts. With 15 samples, nearest-rank p95 is the observed maximum. These variable
samples neither attribute the remaining gap to Close nor establish statistical equivalence.
G2 remains open; no artificial scheduling delays were introduced.

### Concurrent spider: DATA phases and non-writing cleanup, 2026-10-04 (preceding checkpoint)

DATA now publishes its body and accounts flow before waiting for cc.wmu. Padding credit has a saved
writer phase, and reset/END_STREAM follows the actual WINDOW_UPDATE Flush completion.
Forgotten-stream DATA refunds connection credit through that same phase. Non-writing cleanup
has explicit readiness in wait/step as well as the cleanup scan; forgetting a stream precedes
its final cc.wmu wait, including behind an unfinished request Write. Independent cleanup
readiness does not grant Do permission to produce a conflicting Write.

`test-fetch-cleanup` adds 13 cases driven through public feed/wait/step/take/write_complete,
with white-box observations of body, flow accounting, stream removal and done. They exercise
busy/free writers, both DATA completion boundaries, forgotten-stream DATA, later input for
a forgotten stream, stop/error, no duplicate output and resumption without new input. Five
local owner-predicate cases remain as supplementary coverage. The saved-source fetch test
now expects one non-writing cleanup turn before its source-Write wait.

A fresh copy of the complete current tracked/unignored source manifest, with only vendor/dl
dependency seeds and no copied build objects, passed offline
`make -j4 BUILD=build-frozen check`. It includes both HYSTERIA planes, MIPS/AArch64 builds,
Go consistency checks and 45 AArch64 crypto checks under QEMU. Source checksums before/after
the gate agree. ASan/UBSan with leak detection passes both fetch and driver fixtures; three
TSan fetch runs pass. Sanitizer builds use the existing `-Wno-error=conversion` profile:
an initial strict ASan build stopped at the known prefix.c conversion warning. That initial
log is retained. The driver fixture instruments fetch.c directly and links normal library
objects; this is not complete-tunnel sanitizer coverage or proof of the absence of races.

Logs and the source manifest are under `build-g2-review/continuation-snapshot/`.
The source SHA-256 for fetch.c is
`bb36a598b76579be0ce90b782b2f3039181bc64bd0ea6598e487801514ba245c`.
The isolated source remains in `lc-build:g2-continuation-source`; preparation/resume scripts
are in build-g2-review. Later documentation updates do not change the tested source copy.

The working-tree export checker is now `scripts/lite-client-public/check-current.sh` in the
monorepo. It enumerates cached index paths (including staged additions) plus unignored new
paths, copies current bytes and omits deletions. It requires all literal src/test build inputs
named by executable Makefile lines, then checks forbidden artifacts and publication leaks.
The ignored check-current-export.sh wrapper delegates to it. This checks a working-tree
scratch export; export.sh still publishes committed content only.

Three paired rounds completed after the build/sanitizer jobs, with five connections per
client/scenario/round: 15/client/scenario, 120 total. Raw dest logs produce exactly five valid
timing samples in all 24 groups; stdout skeletons are not counted. Snapshot, post-run snapshot
and all three executed-copy SHA-256s agree:
`3c73ebb5d3ba095a996bfe62c3519d914889e6055de866963b6a3fea0d8de80b`.
The source manifest also agrees before/after measurement. The initial offline stand attempt
could not fetch missing pinned Go modules and produced no samples; its log is retained.
The successful stand container had dependency-download access. The lite-client binary was
not rebuilt during those rounds. Raw logs, hashes, connections.csv and summary.csv are in
`build-g2-review/continuation-snapshot/measure/`.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 5 / 10 | 471 / 419 | 765 / 1099 |
| gzbody | 1 / 0 | 451 / 559 | 2346 / 1961 |
| latebig | 15 / 15 | 406 / 334 | 2133 / 1020 |
| closeafter | 0 / 0 | 402 / 342 | 577 / 946 |

Bigbody CANCEL differs by 33.3 percentage points and fails the 10-point criterion; its
per-round ref/lc counts are 4/5, 1/3, 0/2. Absolute median gaps are 52/108/72/60 us, so gzbody
also fails the 100 us criterion. Closeafter harvested-path draws are 12/15 vs 10/15, not
commit counts. Nearest-rank p95 with 15 samples is the observed maximum. These variable
samples do not establish causality or statistical equivalence. G2 remains open: production
DATA/cleanup boundaries now have regression evidence, while conservative producer gating
and wire cancellation/timing differences remain. No scheduling delays were introduced.

The final working-tree export check, with source and working notes mounted read-only,
passes with 531 files and all literal src/test Makefile inputs present. git diff --check
passes. This validates the updated report/export, not a new compiled-source checkpoint.

### Concurrent spider: request and writing-cleanup owners

All completion-mode request HEADERS, including single-frame requests, now
use the retained request continuation. `request_writer` owns cc.wmu through
its final Flush Write id; only successful matching completion releases it,
frees the retained HPACK block and marks sent_end_stream. Intermediate Writes
of multi-frame headers retain ownership. The pinned header writer holds
`cc.wmu` across its Flush (`vendor/x-net/http2/transport.go:1221--1255`).
Previously only multi-frame requests held the logical owner, so a PING could
produce its ACK before an ordinary single-frame Flush had completed.

Writing cleanup now retains a per-ClientConn cleanup_writer through its final
reset/Flush Write id. Successful matching completion releases that owner and
finishes pending cleanup (done and stream forget) without waiting for global
queue emptiness or a second worker cleanup turn. Duplicate completion still
fails; failure closes the fetch rather than releasing a successful owner.
The readLoop preserves writing frames behind request, body and cleanup
owners; non-writing SETTINGS ACK and ordinary DATA remain independent.
No socket I/O or blocking lock wait occurs under the physical fetch mutex.

New single-frame regressions check non-writing SETTINGS ACK interleaving,
saved PING plus a feed tail, absence of preconstructed ACK at owner release,
exact nonce, stop/error and caller-owned request bytes after destruction.
The cancellation/redirect fixture holds a PING behind cleanup Flush and
checks its ACK completes without duplicate CANCEL or premature HEADERS.
The actual worker/TLS fixture holds HEADERS on socket EAGAIN, accepts SETTINGS
ACK, suspends PING and the next buffered TLS record, then decrypts exactly
the retained single-frame request and saved-nonce ACK in TLS sequence order.

Normal fetch/tunnel, ASan/UBSan with leak detection and three TSan runs of each
fixture exit 0. Final normal host sample for 64 workers: RSS 9428 KiB from
2240 KiB baseline, startup CPU 8527 us, lifecycle CPU 10973 us, post-join RSS
7036 KiB and 8 MiB virtual stack reserved per pthread. These are host resource
samples, not measurements on loaded routers.

Final offline `make -j4 BUILD=build-g2-gates check` exits 0 in
`lc-build:g2-offline-seeded` with `--network none`: both HYSTERIA planes,
MIPS/ARM64, pinned unskipped x509-limbo and 45 QEMU crypto checks. The full log
includes final single-frame stop/error and cleanup/PING regressions. Check
wrappers are `build-g2-worker/check-foreign-final.sh` and
`verify-foreign-final.sh`; copied full/normal/sanitizer logs are under
`build-g2-worker/verification/request-owner/` (saved by
`save-request-owner-checks.sh`).

After all check/build jobs finished, three fresh unprofiled paired rounds
completed: five connections/client/scenario/round, 15/client/scenario, 120
total. Immutable snapshot, post-run snapshot and all three executed-copy
SHA256s agree:
`7a1bd3362b2e9397efd595667719cd3299b3f037d3e71423b646237108a7a82c`.
Raw dest/tunnel and round logs, hash files, `connections.csv` and `summary.csv`
are in `build-g2-worker/spider-after/request-owner/`. Parsing uses raw dest
logs only, requiring five connections with valid timing in all 24 groups;
stdout skeleton repetitions are not counted.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 3 / 11 | 283 / 326 | 1039 / 679 |
| gzbody | 0 / 0 | 263 / 339 | 476 / 850 |
| latebig | 15 / 15 | 287 / 362 | 581 / 681 |
| closeafter | 0 / 0 | 316 / 241 | 503 / 817 |

Nearest-rank p95 at n=15 is the observed maximum, not a reliable tail estimate.
Absolute median gaps 43/76/75/75 us meet the 100 us timing criterion. Bigbody
CANCEL differs by 53.3 percentage points and fails the 10-point criterion;
per-round ref/lc counts are 1/2, 0/4, 2/5, each from five connections/client.
All other scenarios have zero CANCEL difference. Closeafter harvested-path
draws are 12/15 ref vs 11/15 lc, not page-commit counts, because seeded `/`
remains selectable. These small variable samples do not establish statistical
equivalence or a causal improvement relative to previous snapshots.

G2 remains open. Own-id completion releases single/multi-frame request and
writing-cleanup owners, but starting/resuming producers still has a conservative
global queue barrier. Non-writing cleanup's final cc.wmu/werr check and donec
timing (`vendor/x-net/http2/transport.go:1370--1378`) are not modeled as a
separate lock acquisition; neither is every padded-DATA side-effect boundary
before a refund Write. The cancellation failure is not attributed to one of
these remaining boundaries without evidence. No scheduling delays, fallback
consumer or router deployment were added.
The final scratch public/API check exits 0 after the report updates: 530 files
fit to publish, source and working notes mounted read-only, no public-checkout
writes. `git diff --check` exits 0.

### Earlier checkpoint: body-credit Flush owns cc.wmu

The following body-owner checkpoint describes its recorded acceptance binary,
not the later request/cleanup-owner changes above.

Completion mode now retains the transport body Read's ClientConn writer owner
through its final WINDOW_UPDATE Write completion. The pinned
`vendor/x-net/http2/transport.go:2211--2223` acquires `cc.wmu`, writes flow
credits and Flushes before releasing it. A non-ACK PING likewise acquires that
lock before producing its ACK (`vendor/x-net/http2/transport.go:2671--2678`).
Previously C generated that ACK behind an in-flight body Flush: socket Write
order was preserved, but readLoop dispatch had already bypassed the lock.

Each ClientConn now retains a source_writer while that Flush owns cc.wmu.
Writer-needing frames keep their complete frame, bufio fill and one accepted
feed tail until that owner completes; read_ready suspends further TLS Reads.
Ordinary non-writing DATA still reaches the pipe during the body Write, as
before, allowing the owned source result to survive compaction/reallocation.
On successful completion of the body's final Write id the lock is released;
the worker can dispatch the saved PING, and plain/gzip Read returns its saved
bytes even while the new ACK waits on the socket. The physical fetch mutex is
not held across socket I/O or a writer wait. Synchronous diagnostic behavior
is unchanged. Request/cleanup producers still have their conservative barrier;
this is not a complete Go lock/scheduler model.

Plain/gzip regressions require no ACK output after the body completion but
before saved-frame dispatch, then require exact ACK identity and eventual
harvest. Further plain/gzip cases stop or fail the body Write while its reader
waits on cc.wmu, with retained source bytes and decoder state freed safely;
caller-owned whole Write remains valid after fetch destruction. The actual
tunnel fixture backpressures a real TLS WINDOW_UPDATE, receives PING, preserves
the following buffered TLS boundary, then decrypts exactly the original credit
Write and saved-nonce ACK in TLS sequence order after real socket completions.

Final normal fetch/tunnel and ASan/UBSan with leak detection pass, as do three
TSan runs of each fixture (all exit 0). The final normal 64-worker host sample:
RSS 9436 KiB from a 2316 KiB baseline, startup CPU 10240 us, lifecycle CPU
12828 us, RSS after join/reap 7040 KiB, 8 MiB virtual stack reserved per pthread.
These are host samples, not loaded-router measurements.

The final frozen checkpoint also passes `make -j4 BUILD=build-g2-gates check`
in `lc-build:g2-offline-seeded` with `--network none`, exit 0. Both HYSTERIA
planes, MIPS/ARM64, pinned unskipped x509-limbo and 45 QEMU crypto checks run.
The full log includes the final added body-writer stop/error cases, not only
the earlier normal suite. Copies of normal/full-gate and sanitizer logs live
in `build-g2-worker/verification/body-lock/`. Wrappers:
`check-foreign-final.sh`, `verify-foreign-final.sh`, `save-body-lock-checks.sh`
under `build-g2-worker/`. An intermediate combined check/measure container
was stopped because its gate lacked `--network none`; it is not acceptance
evidence. The final gate above is the separately repeated offline run.

After all build/sanitizer jobs ended, three fresh unprofiled paired rounds
completed: five connections per client/scenario/round, 15 per client/scenario,
120 total. Immutable snapshot, post-run snapshot and all executed-copy SHA256s:
`51f030ce5ede27ef7496a1abae6699839f533a1e012c0c063d8c3645309ee18a`.
Artifacts: `build-g2-worker/spider-after/body-lock/`, containing raw
`dest-{1,2,3}.log`, `tunnel-{1,2,3}.log`, round logs, hash files and
`connections.csv`/`summary.csv`. Counts/timings use only raw dest logs, not
duplicated stdout summaries; all 24 groups must contain five valid timings.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 2 / 11 | 361 / 333 | 2073 / 1362 |
| gzbody | 1 / 0 | 305 / 399 | 545 / 821 |
| latebig | 15 / 15 | 274 / 267 | 396 / 928 |
| closeafter | 0 / 0 | 345 / 266 | 486 / 803 |

Nearest-rank p95 at n=15 is the observed maximum. Median absolute gaps are
28/94/7/79 us, within the 100 us criterion. Bigbody CANCEL differs by 60
percentage points and fails the 10-point criterion; per-round ref/lc counts
are 2/5, 0/3, 0/3 (five connections/client/round). Gzbody differs by 6.7
points; the other two scenarios by zero. Closeafter harvested-path draws are
12/15 ref and 11/15 lc, not page-commit counts: seeded `/` remains selectable.
Small variable samples do not establish statistical equivalence or attribute
frequency changes from the earlier checkpoint to this lock fix.

G2 remains open. The body Flush owner and PING/TLS boundary are exercised,
but request/cleanup producer acquisition remains conservatively queue-gated.
Request cc.wmu ownership currently covers multi-frame continuations, not all
single-frame pending HEADERS Writes; cleanup ownership also needs a general
writer model. The readLoop's whole-frame preview/deferral is not proof of Go's
side-effect timing before padded DATA refund Writes. No timers, scheduling
delays, fallback driver or router deployment were introduced.
The final scratch public/API checker exits 0 after the report updates:
530 files fit to publish, source and working notes mounted read-only, no
public-checkout writes. `git diff --check` also exits 0.

### Earlier checkpoint: opening Flush starts the readLoop

The following opening checkpoint describes its recorded acceptance binary,
not the later body writer-owner change above.

Completion mode now starts each ClientConn's readLoop only when its own
opening Write succeeds. The pinned `vendor/x-net/http2/transport.go:538--554`
Flushes preface/SETTINGS/connection WINDOW_UPDATE, checks the result, then
starts `go cc.readLoop()`. Previously C marked the new reader ready immediately,
including while the opening ciphertext was still blocked on socket EAGAIN.

Each ClientConn retains its opening Write id. A successful matching completion
starts its reader and assigns its read-order sequence; take alone does not.
This is not a global queue-empty condition: a pending first-request Write
does not keep the reader from starting. New connections on the same TLS
transport wait on their own opening, without disabling existing readers.
The synchronous diagnostic driver keeps its legacy behavior and clears the
opening id when take accepts that Write. A completion-mode feed made before
startup retains its one bounded input tail for later dispatch; production
checks read_ready before decrypting or reading another TLS record.

Fetch regressions check queued/taken opening readiness, startup despite a
pending request Write, and early SETTINGS dispatch only after opening
completion, followed by its separately acknowledged ACK. The real worker
fixture fills the socket to EAGAIN and leaves a complete invalid TLS record
buffered: the pump must preserve it without opening it or reporting loss,
then stop/join/free the outstanding opening safely. This fixture initially
failed to compile because it called a nonexistent rx_append helper; the final
test uses the existing session buffer and passes the strict normal build.

Validation exits 0: `make -j4 BUILD=build-g2-gates check` in
`lc-build:g2-offline-seeded` with `--network none`, including both HYSTERIA
planes, both router architectures, pinned unskipped x509-limbo and 45 QEMU
crypto checks. Normal fetch/tunnel, ASan/UBSan with leak detection and three
TSan runs of each fixture also exit 0. The command wrappers are
`build-g2-worker/check-foreign-final.sh` and `verify-foreign-final.sh`;
copied logs are in `build-g2-worker/verification/opening-read/`, retaining
this checkpoint independently of the shared verification filenames.
The scratch public/API checker exits 0 after these documentation updates:
530 files fit to publish, with the source and working notes mounted read-only;
only a disposable export is written, not a public checkout.
Normal 64-worker host resource sample: RSS 9504 KiB from 2408 KiB baseline;
startup CPU 9019 us, lifecycle CPU 11682 us, post-join RSS 7100 KiB;
8 MiB virtual stack reservation per pthread. These are not router-load figures.

Fresh unprofiled acceptance measurements were run after those jobs finished:
three paired rounds, five connections/client/scenario/round, 120 total and
15/client/scenario. Snapshot, post-run snapshot and all executed-copy hashes:
`91e346abaa89180b750787ddc0f58ce68568c5db52442f4fdec1c597b7be891a`.
Raw dest/tunnel and round logs, hashes and per-connection/distribution CSVs
are in `build-g2-worker/spider-after/opening-read/`. The parser reads only raw
dest logs and rejects missing groups/timestamps or counts other than 120.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 7 / 14 | 366 / 361 | 659 / 723 |
| gzbody | 0 / 0 | 274 / 322 | 1687 / 772 |
| latebig | 15 / 15 | 275 / 243 | 807 / 709 |
| closeafter | 0 / 0 | 355 / 280 | 558 / 705 |

Nearest-rank p95 at n=15 is the maximum, not a stable tail estimate. Absolute
median gaps 5/48/32/75 us meet the 100 us criterion. Bigbody CANCEL differs
by 46.7 points and fails the 10-point criterion; per-round counts ref/lc are
3/5, 2/5 and 2/4. Other scenarios have zero CANCEL difference. Closeafter
harvested-path draws are 6/15 ref and 11/15 lc, not harvest-commit counts:
seeded `/` remains selectable. These small, variable samples do not establish
statistical equivalence or attribute the change from the earlier run to the
opening fix. G2 stays open because CANCEL fails and request/cleanup producer
lock acquisition plus readLoop interleaving behind body-credit Writes are
not established as Go-equivalent. No scheduling delays, fallback driver or
router deployment were introduced.

### Earlier checkpoint: independent body work behind readLoop Writes

The following body checkpoint's measurements describe its recorded binary,
not the later opening-read boundary above.

Completion mode no longer blocks all Do work just because a readLoop's PING/SETTINGS
Write is queued or in flight. It uses the retained Write owner to permit response handling,
plain/gzip body reads, harvest and non-writing body Close while that readLoop remains
blocked. The ACK is neither acknowledged nor bypassed, and its saved input/TLS read boundary
remains suspended. Request/cleanup producers and operations that need another Write still
use the conservative producer barrier; this is not a complete Go scheduler/writer model.

A transport body Read that refunds flow credit now consumes/accounts its pipe bytes once,
retains an owned copy and the two credit increments, then waits to issue the natural
WINDOW_UPDATE Flush. It returns those bytes to plain/gzip only after its final Write id
is acknowledged. A later foreign ACK does not prolong that own-Write wait. The owned
result survives pipe compaction/growth and gzip WAIT without keeping an unlocked pipe
pointer or blocking socket I/O under the fetch mutex. At most one result is retained per
source Read, sized by the natural Read, not an artificial cap. Non-barrier diagnostic
settle preserves its synchronous contract. Page harvest and deferred body Close are now
distinct Do continuations; clean Close can end Do while the foreign ACK remains blocked.

New fetch regressions cover small plain/gzip harvest behind an uncompleted ACK, large
plain/gzip flow-credit waits, the body's own Write completing ahead of a later queued
ACK, two PING identities, stop/error with retained bytes/decoder state and pipe
compaction/reallocation during a pending Read. GOAWAY/do-not-reuse Close is not treated
as read-only: forgetting its final stream can close the whole transport and must wait
behind the foreign Write. Plain/gzip GOAWAY cases check harvest precedes that deferred
close. The actual tunnel fixture receives real
TLS records containing HEADERS/DATA/END_STREAM/PING and holds its ACK behind socket
EAGAIN. The real worker harvests and ends Do before that socket drain; the peer decrypts
the original ACK afterward and then the next PING ACK on the same live TLS connection.
These are content/readiness predicates, not a fixed consumer turn count or delay.

Final validation of this checkpoint exits 0: offline
`make -j4 BUILD=build-g2-gates check` in `lc-build:g2-offline-seeded`
with `--network none`. It includes both HYSTERIA planes, MIPS/ARM64 builds,
unskipped pinned x509-limbo verification and 45 QEMU crypto checks. Its final
log is `build-g2-worker/verification/foreign-full-final.log`. The final normal
fetch/tunnel fixtures pass (`foreign-fetch.log`, `foreign-tunnel.log`);
ASan/UBSan with leak detection passes for both fixtures (`asan.log`,
`tunnel-asan.log`), as do three TSan runs of each (`tsan-{1,2,3}.log`,
`tunnel-tsan-{1,2,3}.log`). These logs share that verification directory.
The sanitizer builds relax pre-existing conversion-warning errors, not runtime
sanitizer failures; the normal strict gate is unchanged.
The final scratch public/API checker also exits 0: 530 tracked/unignored files
fit to publish, with working notes checked and both inputs mounted read-only.
It writes only a disposable export, not a public checkout.

The normal host fixture's 64 simultaneous workers used 9504 KiB RSS from a
2364 KiB baseline; startup CPU was 10038 us and total lifecycle CPU 13138 us.
RSS after join/reap was 7088 KiB; each pthread reserves an 8 MiB virtual stack.
These are host-fixture resource samples, not measurements on loaded routers.

The ordinary, unprofiled binary was measured after all build/sanitizer jobs had
finished: three paired rounds, five connections per client/scenario per round
(15 per client/scenario, 120 total). The immutable snapshot, its post-run hash
and all three executed-copy hashes agree:
`de274c8e3b655129d3cbea6c80fd11a436ac14d35243f0d8c086734205bb3e83`.
Artifacts are under `build-g2-worker/spider-after/foreign-body/`: raw
`dest-{1,2,3}.log`, `tunnel-{1,2,3}.log`, round logs, binary hashes,
`connections.csv` and `summary.csv`. Counts and timings come from the raw dest
logs, not repeated stdout summaries. The parser requires all 24 groups to have
five connections and valid first-request timestamps.

| Scenario | CANCEL ref / lc (out of 15 each) | Median first request ref / lc (us) | p95 ref / lc (us) |
| --- | --- | --- | --- |
| bigbody | 4 / 15 | 346 / 325 | 672 / 1403 |
| gzbody | 1 / 0 | 289 / 380 | 1352 / 971 |
| latebig | 15 / 15 | 315 / 302 | 666 / 1168 |
| closeafter | 0 / 0 | 318 / 298 | 798 / 680 |

Nearest-rank p95 with 15 samples is the observed maximum. Median absolute gaps
are 21, 91, 13 and 20 us, meeting the 100 us timing criterion for this run.
Bigbody CANCEL differs by 73.3 percentage points and fails the 10-point
criterion (per-round counts ref/lc: 0/5, 2/5, 2/5). Gzbody differs by 6.7
points; latebig and closeafter by zero. Closeafter selected a harvested path
12/15 times in both clients; this is not a page-commit count, since the seeded
`/` remains a selectable path. Do not infer lost harvest from that draw.

G2 remains open. These regressions establish independent read-only Do/body
work behind foreign readLoop Writes and resumable own-credit Reads; they do
not establish Go-equivalent request/cleanup lock acquisition, every initial
read boundary while the opening Write is backpressured, or general readLoop
interleaving behind body-credit Writes. The cancellation distribution does
not identify one of those remaining boundaries as its cause. No production
scheduling delays or fallback consumer were added; no router was deployed.

### Earlier checkpoint: startup profiling and initial Write

The following older checkpoints describe their recorded snapshots, not the latest
barrier semantics or acceptance run above.

`LC_SPIDER_PROFILE=1` is an opt-in diagnostic compile flag, not a production scheduling
mode. It records monotonic nanosecond offsets for browser/fetch construction, pthread
creation/entry, opening Write completion, eventfd dispatch and the first request's socket
completion. The worker release-publishes up to 16 immutable wait/step samples; only the
event loop prints them, after the first stream-one HEADERS Write completes. There are no
extra wakes, delays or consumers. Ordinary builds compile out all profiling fields and
calls. Profiled stand timings are diagnostic evidence, not G2 acceptance measurements:
the clocks/atomics and post-request logging can perturb scheduling and cancellation.

The profile identified an initial-output dependency: fetch construction queued the
preface/SETTINGS, and the worker's completion-aware wait correctly blocked on that Write.
Startup did not drain it. Only a later incoming application-data feed or eventfd callback
would do so; peer DATA therefore determined when the opening Write was submitted, and a
peer waiting for the preface could wait indefinitely. `spider_start` now starts the worker
and immediately drains the existing whole Write, before pumping/arming peer reads. This
is submission of already queued output, not a second Do/settle driver.
The pinned reference likewise writes the preface, SETTINGS and connection WINDOW_UPDATE,
then Flushes before starting `cc.readLoop` (`vendor/x-net/http2/transport.go:538--554`).
This submission fix does not by itself prove that every initial-read interleaving under
socket backpressure matches that reference initialization boundary.

The actual socketpair fixture now starts without supplying any peer bytes. It checks the
preface is submitted immediately, waits on real eventfd readiness for the request, and
decrypts exactly the opening and stream-one HEADERS Writes in order. A second startup
case begins with a full socket, retaining the pending opening Write through stop/join/free.
The profiling build additionally exercises release/acquire publication before logging.

The pre-fix diagnostic snapshot completed three paired rounds, 60 profiled lite-client
connections (15/scenario). Snapshot and all executed hashes agree:
`10a4ff1b790d72e257104fd57398a096c4a08bf2fe388eaf7cf2ed7c87a195f1`.
Raw logs, phase samples and distributions are in
`build-g2-worker/spider-after/profile-startup/`. Median offsets/durations, in microseconds:
fetch/browser setup 31.8; pthread_create call 66.4; create-to-thread-entry 85.8;
opening socket completion 345.4; first-request socket completion 471.1; summed step
calls 17.0; last completed step to request socket completion 44.7. Offsets start just
before browser/fetch construction, not at the peer's handshake end. Step duration
includes mutex acquisition and protocol work; it does not isolate lock contention.
The delayed opening is consistent with the source dependency above, not evidence that
pthread creation alone explains G2. All these figures describe the pre-fix profile build.

Post-fix validation exits 0: `make -j4 BUILD=build-g2-gates check` in the pinned
offline-seeded image with `--network none`, including HYSTERIA=0/1, MIPS/ARM64 both
planes, unskipped Go x509-limbo verification and QEMU's 45 crypto checks. The full
log is `build-g2-worker/verification/startup-full-check.log`. The normal HYSTERIA=0
fixture log is `startup-normal.log`; current non-profile ASan/UBSan (leak detection)
and three TSan runs are `tunnel-asan.log` and `tunnel-tsan-{1,2,3}.log`. The opt-in
profiling fixture also passes normal, ASan/UBSan and three TSan runs; its logs use
the `profile-` prefix under the same directory. The scratch public/API check passes
for 530 tracked/unignored files, with working notes included and no public-checkout
write. The earlier failed normal runs were fixture mistakes (epoll reports the endpoint
via `event.data`, not `event.fd`); they are not passing evidence. The final fixture
checks endpoint readiness and does not require a fixed worker turn count.

The ordinary (non-profile) post-fix binary completed three fresh paired rounds after
all build/sanitizer gates finished. SHA-256:
`efd16222999f01b79eb67f2782c1fb5c0bc6a17ad9dd69bade2a0d281c462cb6`.
All snapshot and per-round executed hashes agree. The raw dest/tunnel logs and
per-connection/distribution CSV are in `build-g2-worker/spider-after/startup-drain/`.
The parser requires exactly 120 connections, five complete timing samples in every
round/scenario/client group; stdout skeletons are not included.

| Scenario | CANCEL ref/lc (of 15) | Median ref/lc, us | p95 ref/lc, us |
|---|---|---|---|
| bigbody | 4/11 | 347/318 | 1890/820 |
| gzbody | 0/0 | 362/351 | 752/906 |
| latebig | 15/15 | 345/263 | 738/874 |
| closeafter | 0/0 | 355/290 | 697/760 |

All first-request median gaps (29, 11, 82, 65 us) now meet the 100 us checkpoint
threshold. G2 still fails: bigbody's cancellation gap is 46.7 percentage points.
Closeafter harvested-path reuse is 12/15 versus 10/15. The small sample does not
establish statistical equivalence, and nearest-rank p95 is again the maximum.
Reuse is not a harvest-commit counter: `paths.c` keeps the initial `/` alongside
harvested paths and can draw it again, so a later `/` alone does not prove a lost commit.
The no-input socket regression proves the startup dependency was removed; these
changing reference samples do not isolate the size of its latency effect from
other host scheduling variation. Next work is the readLoop/Do interleaving around
the remaining global barrier and distinguishing closeafter commits from random path reuse,
including the initial
read boundary under opening-Write backpressure, not timing delays or deployment.

### Concurrent spider: bounded production checkpoint

In completion-aware tunnel mode a multi-frame request retains its encoded HPACK block,
stream owner and offset. Each step produces one natural Framer batch rather than all
HEADERS/CONTINUATIONs at once. bufio's 4096-byte buffering and direct-write bypass are
unchanged: this does not split a TLS Write or introduce an artificial request-size limit.
The final flush must complete before the request writer releases its logical cc.wmu.

Queued Writes now carry a unique id and owner. Cleanup retains the id of its last Write;
done/forget and redirect continuation follow its completion, without repeating CANCEL.
A readLoop that emitted protocol output likewise waits for its last Write. One feed's
unread tail and its complete pending frame are retained, and the tunnel consults
`lc_spider_fetch_read_ready` before opening another TLS record. Completion and worker
notifications resume buffered TLS input without a timer or polling loop. Non-writing
control frames do not wait behind a header writer; DATA's flow refund is previewed on
copies of the flow state to identify operations that need the writer.

This bounds materialized output per resumable operation, not arbitrary header/body/path
content. A Framer batch can naturally produce more than one bufio Write; cleanup's fixed
WINDOW_UPDATE/RST/PING operations remain whole. The global consumer output barrier still
remains and is not a proof of Go scheduler equivalence. The synchronous diagnostic
`spider_run`/`settle` path retains its separate non-completion contract and is not used by
the tunnel worker.

`test-fetch` now decodes a complete 96 KiB header value across request continuations,
checks SETTINGS/PING do not interrupt the header block, exercises stop/error with retained
input and headers, and verifies 64 sequential PING ACKs resume by completion identity
without a new input notification. These pass normally, with ASan/UBSan leak detection and
three TSan runs. The actual tunnel fixture also passes normally, ASan/UBSan and three TSan
runs (sanitizer scope/flags are described below).

The current-code offline command `make -j4 BUILD=build-g2-gates check` exits 0 in
`lc-build:g2-offline-seeded` with `--network none`, including host HYSTERIA=0/1 builds,
MIPS/ARM64 both planes and QEMU. Log:
`build-g2-worker/verification/bounded-full-final.log`. Normal fixture logs are
`bounded-fetch.log` and `bounded-tunnel.log`; sanitizer logs retain their documented names
under the same verification directory. Measurements for this checkpoint are recorded
separately from the earlier whole-Write checkpoint below.

The bounded-production snapshot completed three paired rounds with 15 connections per
client/scenario and no concurrent lite-client build/sanitizer gates. SHA-256:
`8bda454aea85c3603a8de03eae3d5413bc873b84c1bbf637b58ec2ae8d72a6a3`.
All snapshot/before/after and executed-round hashes agree. Raw dest/tunnel logs,
per-connection CSV and summary are under
`build-g2-worker/spider-after/bounded-production/`; stdout skeletons are not counted.

| Scenario | CANCEL ref/lc (of 15) | Median ref/lc, us | p95 ref/lc, us |
|---|---|---|---|
| bigbody | 7/13 | 394/518 | 1125/997 |
| gzbody | 1/0 | 339/468 | 688/998 |
| latebig | 15/15 | 367/520 | 1412/1328 |
| closeafter | 0/0 | 387/547 | 1389/1228 |

Closeafter harvested-path reuse is 12/15 versus 11/15. G2 still fails: bigbody's
cancellation gap is 40 percentage points and all median gaps (124--160 us) exceed
100 us. With 15 samples, nearest-rank p95 is the maximum, not a resolved tail estimate;
changes in reference counts also preclude attributing differences between checkpoints
to the continuation change alone. Profiling worker startup, mutex/eventfd handoff and
the remaining global barrier is the next step before selecting a scheduler change.

In the current HYSTERIA=0 tunnel fixture, 64 live workers used 11520 KiB RSS against
a 2292 KiB baseline, with 9294 us cumulative startup CPU and 11821 us total lifecycle
CPU. Each live pthread reserved 8 MiB of virtual stack, not resident memory. This is
host fixture evidence, not a loaded-router measurement.

The scratch publication/API check also exits 0 for 530 current tracked/unignored
files, with working notes included. It uses a disposable export in the checker
container; no public checkout, installed binary or router was changed.

The independent copied-tree clean gate with the corrected seam binary path completed
with exit 0 and no network. Its log is `build-g2-review/isolated-fixed-gate.log`.
It validates that copied checkpoint, not later concurrent edits. A subsequent review
of current fetch, tunnel handoff and record suites also passed (exit 0).

The diagnostic startup profile completed three paired rounds, with all five hashes
equal (`10a4ff1b790d72e257104fd57398a096c4a08bf2fe388eaf7cf2ed7c87a195f1`).
Across 60 local sessions, median fetch construction was 31.8 us, pthread_create 66.4 us,
created-to-worker-entry 15.1 us, base-to-opening 345.4 us, opening-to-request 124.6 us
and base-to-request 471.1 us. The opening-to-request interval includes protocol work,
mutex/wakeup and event-loop scheduling; it is not a pure eventfd latency measurement.
Instrumented CANCEL ref/lite counts: bigbody 5/9, gzbody 2/0, latebig 15/15,
closeafter 0/0 (15 connections each). Request medians ref/lite in us: 379/560,
375/599, 374/473, 436/579. Closeafter reuse was 12/15 each. Diagnostic timing is
not an uninstrumented acceptance run; G2 remains open. Artifacts and CSV are under
`build-g2-worker/spider-after/profile-startup/`.

### Gate commands and levels

```sh
docker run --rm -i --network none -v "$(pwd):/w" -w /w lc-build:local make check
```

`--network none` is deliberate. The image resolves every Go module at build time, so the gate proves
that it needs nothing outside the tree. `rm -rf build &&` in front proves it from a clean state.

What it does, in order:

1. `all`: every program builds on the host, before any assertion runs. The suites link the modules
   they test directly, so without this step a program could fail to build while every suite passed.
2. Every suite in `TEST_NAMES` runs with a 120 second timeout. A suite fails if it exits non-zero,
   if it does not finish in time, or if it prints no `ok` line at all. The last rule exists because a
   suite whose case list stopped being reached exits zero and prints its happy closing line.
3. `check-builds`: the consistency checks listed below, both plane configurations built into
   separate directories, and two build-system checks.
4. `check-device`: every program cross-built for mipsel and aarch64, each with and without the
   Hysteria2 plane.
5. `check-arm64`: the AEAD suite built for aarch64 and run under qemu.
6. `check-x86`: the AEAD suite under five QEMU x86 CPU profiles, asserting both hardware dispatch
   and the generic path when each required instruction feature is absent.

A failure in step 2 prints `FAIL` lines, but a broken build prints none: check the exit code of
`make check`, not the absence of `FAIL`. On 26 September the gate counted 2,057 checks.

To run one suite: `make build/test-<name> && build/test-<name>`, inside the image.

### REALITY spider scheduling race (G2)

As of 2026-10-03, `lc-tunnel` enables the fetch write barrier and starts one Do-consumer thread for
each `ST_SPIDER` session. The event loop remains the sole owner of the socket, TLS keys, record
opening, KeyUpdate replies and `to_up`; the worker owns only `lc_spider_fetch_wait/step`. An eventfd
wakes the loop for complete protocol writes. A write is acknowledged to the worker only after all
of its ciphertext has left `to_up`, including partial-write/EAGAIN cases. Session teardown stops and
joins the worker before freeing the fetch, and socket loss is handed to the worker so bytes already
fed (notably DATA+END_STREAM) receive their final consumer turn first. There is no synchronous
fallback if thread creation fails.

The strict HYSTERIA=0 and HYSTERIA=1 tunnel builds and the normal fetch suite pass with this
integration. The lifecycle/read-boundary/KeyUpdate/backpressure fixture evidence is described below;
fetch-level tests alone are not that evidence. G2 remains open because the paired measurements
have not met its cancellation and latency thresholds.

The first three-round after-worker run (15 connections/client/scenario) exposed two real failures.
First, an EPOLLERR/HUP-only event bypassed EOF handoff; after routing it through the worker, deferred
loss was still applied after the first resumable body read rather than after its saved continuation.
The latter produced 0/15 harvested closeafter paths. Applying loss only on a non-yielded consumer
turn restored closeafter reuse to 12/15 for both clients in a fresh three-round run. Its first-request
medians were 392 us for Xray and 520 us for lite-client: a 128 us gap, still outside G2's 100 us
criterion. These measurements do not isolate the latency of `pthread_create` from mutex contention,
eventfd handoff or event-loop scheduling. Profile those costs before selecting a shared scheduler;
a shared scheduler also needs real retry deadlines, per-session readiness and synchronous draining
of every queued/running session before free. The present per-session worker remains a checkpoint.

`test-spider-tunnel` now uses the actual static tunnel functions and a nonblocking socketpair with
a small send buffer to force EAGAIN. It verifies that an application Write keeps the completion
barrier active, KeyUpdate waits for that Write, and its own reply keeps the TLS read boundary closed
until socket completion, even for complete records already in rawInput. It also injects thread
creation failure and exercises 16 real worker/session stop/join/free cycles behind an outstanding
opening Write. The test is included in `make check`.

The socket owner now retains the whole taken Write and its plaintext offset across EAGAIN,
sealing the next TLS record only after previously queued ciphertext reaches the socket. A
1 MiB Write regression exercises many socket drains, keeps KeyUpdate behind the entire logical
Write, and verifies exact plaintext accounting and one completion. The peer captures and decrypts
every emitted record in sequence and verifies all 1 MiB of content. This bounds the ciphertext
queue, not fetch's production of writes inside a request operation. That preceding checkpoint
left request production open; the bounded production checkpoint above implements its continuation.
The regression also exposed an outgoing full-record limit: sealing now accepts 16384 content
bytes plus the inner type. `test-record` checks that roundtrip and rejection of excess content,
padding and overflowing padding lengths before advancing the sequence number.

The enlarged tunnel regression passes with HYSTERIA=0 and 1, and its HYSTERIA=0 tunnel/core/fetch
code passes ASan/UBSan with leak detection and three TSan tunnel runs. These runs do not instrument
all external decoder/crypto libraries. The O1 sanitizer build keeps pre-existing conversion
warnings nonfatal; normal builds retain the strict warnings. Logs are under
`build-g2-worker/verification/`: `tunnel.log`, `tunnel-hy.log`, `record.log`,
`tunnel-asan-build.log` and `tunnel-asan.log`. The standalone test target explicitly depends
on generated `version.h`, so it can be built in a fresh directory without first building `all`.

The offline full-tree repeat passes (exit 0):
`make -j4 BUILD=build-g2-gates check` in `lc-build:g2-offline-seeded` with `--network none`.
It includes unskipped Go crypto/x509 verification (11167 Verify calls and 4387 policiesValid
calls with no differences), MIPS and ARM64 builds with both HYSTERIA settings and 45 ARM64
crypto checks under QEMU. Log: `build-g2-worker/verification/full-check-repeat.log`.
The final current-tree repeat also exits 0; its log is
`build-g2-worker/verification/full-check-final.log`.
The first cold gate, started before the full-record fix was applied, failed on the large Write
using the earlier TLS object; it is not a passing run. The final position-dependent payload
regression additionally passes normal HYSTERIA=0/1, ASan/UBSan and three TSan runs; its normal
logs are `tunnel-pattern.log` and `tunnel-hy-pattern.log` in the verification directory.

Run it independently:

```sh
make BUILD=build-g2-worker HYSTERIA=0 build-g2-worker/test-spider-tunnel
timeout 30 ./build-g2-worker/test-spider-tunnel
```

The normal fetch suite additionally tests deferred EOF on a 24 KiB page, with its only link in the
last body Read and completion of all generated writes between consumer continuations. END_STREAM
preserves that link; transport EOF without END_STREAM does not harvest the partial page. Normal,
ASan/UBSan with leak detection, and three TSan fetch runs pass. These sanitizer results cover the
fetch boundary; they do not instrument the complete tunnel test or establish G2 timing parity.

The same tunnel test measures 1/16/64 simultaneously live stranger workers, then stops/joins all of
them before reap. In the enlarged test on the x86 Docker host, HYSTERIA=0 RSS was
2280/3724/7420 KiB against a 2280 KiB baseline; cumulative startup CPU was 164/2008/8852 us,
and creation plus teardown cost 11399 us. HYSTERIA=1 RSS was 2304/3644/7340 KiB against
2304 KiB; startup CPU was 171/2255/9333 us and total lifecycle CPU 11995 us.
Each worker reserved an 8 MiB virtual stack (queried on the live pthread),
not 8 MiB resident memory. RSS after teardown remained 7044/6960 KiB: libc can cache stacks and
allocator pages. These are host fixtures waiting behind the opening Write, not loaded router
measurements, and do not isolate first-request latency. Raw logs are in
`build-g2-worker/verification/tunnel.log` and `tunnel-hy.log`.

The post-large-Write exploratory stand completed three paired rounds, 15 connections per
client/scenario. It ran concurrently with build/sanitizer gates, so these timing figures are
not an unloaded acceptance run. The snapshot SHA-256 is
`03e539df9bc6935b8622d108cb0077cc69b687da696e2f33f4b6ebc0b8ff1a5c`;
each round verified the executed binary hash. Raw logs and CSV are under
`build-g2-worker/spider-after/large-write-paired/`.

| Scenario | CANCEL ref/lc (of 15) | First-request median ref/lc, us |
|---|---|---|
| bigbody | 4/12 | 335/515 |
| gzbody | 3/0 | 272/602 |
| latebig | 15/15 | 294/537 |
| closeafter | 0/0 | 306/505 |

Closeafter harvested paths match at 12/15. G2 stays open: these data still show cancellation
and first-request timing differences, independently of the passing socket/lifecycle regressions.
The scratch publication check passes for 530 current tracked/unignored files with working notes
included; no public checkout was written, staged or pushed.

After all parallel build/sanitizer gates finished, a second three-round run used the same
snapshot hash with no concurrent lite-client gate builds. All 15 samples per client/scenario
were parsed from raw dest logs, with min/median/p95/max and per-connection samples saved under
`build-g2-worker/spider-after/large-write-idle/`. Here p95 uses nearest rank and, with only
15 samples, coincides with the maximum; it is not a well-resolved tail estimate.

| Scenario | CANCEL ref/lc (of 15) | Median ref/lc, us | p95 ref/lc, us |
|---|---|---|---|
| bigbody | 3/13 | 323/571 | 504/2270 |
| gzbody | 1/0 | 300/535 | 521/947 |
| latebig | 15/15 | 256/422 | 899/2283 |
| closeafter | 0/0 | 303/452 | 752/2256 |

Closeafter harvested-path reuse is 12/15 versus 11/15. The bigbody cancellation difference
is 66.7 percentage points and median differences are 149--248 us: G2 does not pass even without
the parallel gate build load. That snapshot predates resumable bounded fetch request production
with explicit write ownership, now described above. Profiling scheduling/handoff costs before
any scheduler change remains necessary. The global output completion barrier is not established
as Go-equivalent.

Go runs the REALITY spider's socket readLoop concurrently with HTTP/2 request/Do work. The current
lite-client keeps TLS on the event-loop owner and serializes HTTP/2 state across that owner and
the Do worker using the fetch mutex. Unit tests do not establish scheduling parity and G2 remains
open. The prior fixed-delay experiment (100 µs before
startup, 20 µs before settle) did not converge and was removed; those delays are not part of the
implementation.

#### Historical API-only checkpoints (before tunnel integration)

The following paragraphs record intermediate API-only stages, not the current tunnel state.
Their pending integration/bounded-production claims were superseded by the checkpoints above.

The fetch API now serializes its public operations and transfers each outgoing write as an owned
copy. Its readLoop only notifies body readiness: gzip, body consumption and harvest run on the
consumer's `settle` turn, not inside DATA callbacks. `test-fetch` checks this boundary explicitly
and concurrently exercises feed/settle/take with 64 PING responses. These changes prepare separate
drivers; the tunnel still uses one event-loop driver and G2 remains open. ASan/UBSan and TSan runs
of these tests are correctness checks, not evidence of scheduling parity with Xray.

The consumer notification API (`lc_spider_fetch_wait`/`lc_spider_fetch_stop`) uses a generation
counter under the fetch mutex and a monotonic condition variable. Input-before-wait is retained;
stop is permanent and wakes waiters before their owner joins them. Only the actual retry deadline
uses a timed wait. `test-fetch` checks initial/input notifications and a stop/wait race followed
by join. A REFUSED_STREAM scenario also checks the immediate first retry, no HEADERS during the
second retry's real one-second backoff, notification-free expiry on CLOCK_MONOTONIC, and stream 5
after the consumer advances that expiry. It does not yet deterministically prove stop during an
already-blocked wait. The notification API is not yet connected to a tunnel Do worker.

A separate consumer-thread test drives only `wait`/`settle` on that thread. The owner feeds HEADERS
and DATA/END_STREAM, waits on test predicates (no sleep or polling), and takes the WINDOW_UPDATE
writes produced by body consumption. The consumer is stopped and joined before fetch destruction.
A ten-second condition-variable watchdog bounds test failure; it does not schedule protocol work.
This validates the consumer loop at the fetch boundary, not tunnel TLS ownership, KeyUpdate
handoff, socket read boundaries or write backpressure.

A successful `lc_spider_fetch_take` now advances the consumer generation, so a Do worker waiting
after publishing writes can resume when the TLS owner accepts a complete write. `test-fetch` checks
that notification with a pending PING ACK; HTTP/2 may coalesce protocol frames into one TLS Write,
so the assertion is on complete-write ownership rather than a fixed byte count. This is a wakeup
primitive only: there is not yet a bounded output queue or a producer that can suspend and resume
`settle`, and the tunnel still has one event-loop owner.

`lc_spider_fetch_step` exposes body-Read and Do-transition continuations: it accounts and harvests one returned
plain/gzip read under the protocol lock, then yields with return value 1. No source pointer is kept
across the unlocked boundary. The driver must resume a yielded step without waiting for new DATA.
Tests cover plain-body continuation with a PING processed between steps and gzip continuation to
checked EOF. A committed Do transition also yields before the next transition; the next call can
report that the request waits for input rather than yielding forever. This is not yet a write-completion barrier or bounded scheduler: request encoding,
cleanup and gzip source reads can still publish multiple writes in one step. Tunnel integration
and after-worker measurements remain pending; the baseline below is unchanged by this unused API.

Validated, 2026-10-03 after restoring Docker: the consumer-thread test drives `step` and immediately
resumes return value 1 instead of waiting for another generation. `step` after consumer stop returns
0 without advancing protocol state. Normal test-fetch, ASan/UBSan with leak detection and three
consecutive TSan runs passed. The test does not assume that turn 2 processed HEADERS: take also
notifies the worker, and completion is checked with the body-done predicate instead. These checks
validate the fetch consumer, not tunnel integration or write-completion backpressure.

Redirect Close and the next request now have distinct Do states (`DO_CLOSE`, `DO_NEXT`). A step
can publish the previous stream's cancellation and return before preparing redirect HEADERS;
resumption sends stream 3 without repeating CANCEL. The normal settle driver runs both states
within its turn, preserving existing oracle behavior. The explicit step-order test, normal fetch
suite, ASan/UBSan with leak detection and three TSan runs passed. This creates a continuation
boundary, not an acknowledgment that cancellation bytes reached the socket: a write-completion
barrier and bounded request/cleanup production are still required before tunnel worker integration.

An explicit opt-in write barrier is now available at the fetch boundary. It is enabled before
publication; step returns 2 while queued writes or a single taken write await completion. Taking
bytes does not release this barrier: write_complete confirms success only after the socket accepted
the whole write, or closes the fetch on failure. Tests cover the opening/request barrier, a single
in-flight write, duplicate completion rejection and write failure. The redirect test also checks
CANCEL take -> step still blocked -> completion -> stream 3 HEADERS, without duplicate CANCEL.
Wait now filters input-generation wakes while queued/in-flight writes remain and suppresses the
retry timer during that barrier; stop and connection failure interrupt the wait. Normal fetch,
ASan/UBSan with leak detection and three TSan runs passed. Deterministic input/retry/completion
wait races are not covered yet. No tunnel caller enables this mode: bounded production within an
operation and worker integration remain unimplemented. No after-worker result exists.

A threaded completion-wait test feeds SETTINGS while the opening Write is in flight, then confirms
the opening and its separately queued SETTINGS ACK individually. The waiter returns after barrier
release regardless of thread startup order. Normal fetch, ASan/UBSan with leak detection and three
TSan runs passed. This test does not prove that the waiter entered pthread_cond_wait before input:
deterministic blocked-wait/input/retry tests still remain open. A separate stop test now leaves an
opening Write in flight, stops and joins its completion waiter without acknowledging the write,
destroys the fetch and verifies that the transferred bytes remain the caller's. Normal fetch,
ASan/UBSan with leak detection and three TSan runs passed. It covers stop-before/during-wait races,
not a deterministic proof that the waiter was already blocked inside pthread_cond_wait.

The legacy `settle` entry point now refuses an enabled write barrier with -1 without advancing
protocol state. The barrier ownership test verifies that a mixed driver cannot generate a request
behind the outstanding opening write. Normal fetch, ASan/UBSan with leak detection and three TSan
runs passed. This enforcement is a fetch API guard, not tunnel integration: no tunnel caller
enables the barrier yet and bounded production/socket-path lifecycle tests remain outstanding.

The step driver now yields after one eligible stream cleanup instead of sweeping all streams and
then running Do in the same call. Completion/blocking predicates on the stream are the continuation;
no stream pointer is retained between calls. A finished-response test checks cleanup yields before
Do, resumption completes the response, and no duplicate CANCEL/HEADERS appears. Normal fetch,
ASan/UBSan with leak detection and three TSan runs passed. Legacy settle still performs the full
sweep. This limits cleanup operations per step, not writes inside an individual cleanup or request.

The settle helper now returns immediately if the body reader yielded, before scanning stream
cleanup. Previously a single step could consume body bytes and also run cleanup despite that yield.
The dedicated one-byte DATA/END_STREAM regression test distinguishes body yield, peer-close
cleanup and final Do completion. Removing the immediate return in an isolated build-directory
copy makes exactly its EOF/cleanup assertion fail (mutant test exit 1); the real implementation
passes. Normal fetch, ASan/UBSan with leak detection and three TSan runs passed. The mutation
script and log are under `build-g2-api/check-yield-mutant.sh` and `build-g2-api/yield-mutant.log`;
the production source was not mutated. No tunnel worker or after-worker measurements exist yet.

#### Earlier integration evidence

The pending-transport-EOF regression feeds HEADERS and DATA/END_STREAM without a consumer
turn, then hands off socket loss. Consumer steps must finish Do before reporting connection
closure. Normal fetch, ASan/UBSan with leak detection and TSan pass this case.

Measurement identity must remain constant across all paired rounds: copy the built tunnel to
an immutable snapshot outside the shared build output, run that snapshot, and verify the
executed hash after every round. Do not pool rounds whose hashes differ. The local
`closeafter-continuation` experiment had different executed hashes in rounds 1 and 2 and
is not a homogeneous three-round sample. A fresh snapshot-based run replaces it.

The immutable-snapshot after-worker comparison completed three paired rounds (15 connections
per client/scenario). CANCEL counts Xray/lite: bigbody 3/15 vs 12/15, gzbody 1/15 vs 0/15,
latebig 15/15 vs 15/15, closeafter 0/15 vs 0/15. First-request medians in microseconds:
310/618, 342/562, 302/473 and 386/473 respectively. Harvested-path reuse in closeafter
was 12/15 for each client. All five recorded snapshot/executed hashes agree. These results
fail G2 criteria, particularly bigbody (60 percentage points) and three timing medians.
Raw logs and CSV are in `build-g2-worker/spider-after/snapshot-results/`. This snapshot
predates removal of the stale spider retry deadline from the event-loop timeout calculation;
the latter fix separately passed the strict HYSTERIA=0 tunnel build and fetch tests.

Unicode generated headers are now published through a unique temporary file and rename,
only after the generator succeeds; interrupted generation must not expose truncated output.
Parallel generation of IDNA/NFC/bidi and vectors passed in `build-g2-atomic`. A forced
toolchain failure preserved the old IDNA header hash, but failed in prerequisite setup,
not the table generator itself; it is not a complete generator-failure regression test.
The ignored GOROOT helper modules were restored afterward.

The cached-dependency offline gate container completed with exit 0, including Go verification,
MIPS and ARM64 builds for both planes and 45 ARM64 crypto checks under QEMU. Because its
host output directory showed conflicting intermediate artifacts, an independent repeat runs
from a copied tree inside a network-disabled container. That repeat exited 2: test-seam
executed a hard-coded `build/lc-tunnel` rather than the freshly built binary. Its compile-time
LC_TEST_TUNNEL now comes from BUILD, with no old-binary fallback. The complete seam test
passes with HYSTERIA=1 (exit 0); the HYSTERIA=0 invocation fails its Hysteria-specific
configuration assertions and is not a substitute for the full-plane gate. A clean repeat
with the corrected path remains required.
The current-tree scratch public leak check passes for 530 files with working notes included.
The export contains no vendor payload: only the already tracked `vendor/.gitignore` placeholder.
Audit reports and download/build artifacts are not exported or staged.

The actual tunnel handoff test (`test-spider-tunnel`) passes with HYSTERIA=0 and 1.
It exercises socket EAGAIN, application write completion, pending KeyUpdate reply and
buffered-record read gating, followed by worker teardown and 64 simultaneous sessions.
One x86 resource sample: HYSTERIA=0 RSS 1484 to 7472 KiB, startup CPU 12849 us,
total lifecycle CPU 15505 us; HYSTERIA=1 RSS 2716 to 11572 KiB, startup CPU 9975 us,
total lifecycle CPU 13582 us. Each worker reserved an 8 MiB virtual pthread stack;
this is not resident usage and is not a validated router stack budget. These are single
resource samples, not throughput measurements or a device portability guarantee.

To reproduce the comparison on one x86 host, run at least three paired rounds:

```sh
for run in 1 2 3; do
    docker run --rm -e DEST_TIMING=1 \
        -e 'SCENARIOS=bigbody gzbody latebig closeafter' \
        -v "$(pwd):/repo" lc-build:local \
        sh /repo/tools/vendorcap/spiderredir/run.sh
done
```

Count `RST_STREAM stream=1 CANCEL` as cancellation and a later first request to `/h0`–`/h19` as
`closeafter` harvesting. Exclude attempts with no HTTP/2 preface; collect at least 15 connections per
client and scenario. A future multithreaded implementation may close G2 only after at least three
rounds differ from Xray by no more than 10 percentage points in each scenario and first-request timing
medians are within 100 µs, while passing the TLS read-boundary, unread-byte close/reset, backpressure,
and reader teardown tests. `DEST_TIMING` is diagnostic-only and opt-in; it must not change normal
stand output or protocol behavior.
### The suites

#### G2 baseline, 2026-10-02 (not a worker implementation)

Three fresh paired spiderredir rounds with DEST_TIMING=1, five connections per client per scenario,
used the same host HYSTERIA=0 tunnel binary throughout. The built and executed copies all had SHA-256
`f6b969352a713889421d75d93eb2461c796e06dd2807b8cfb595a13b33d0cc70`.
Counts below exclude the repeated skeleton output and connections without a PREFACE. First-request
times are the destination's first `timing r+... HEADERS1e`, measured from its TLS handshake end.

| scenario | Xray CANCEL / 15 | lite CANCEL / 15 | Xray first-request median, us | lite median, us |
|---|---:|---:|---:|---:|
| bigbody | 4 | 9 | 307 | 85 |
| gzbody | 1 | 1 | 296 | 81 |
| latebig | 15 | 15 | 291 | 80 |
| closeafter | 0 | 0 | 322 | 77 |

In closeafter, a harvested `/hN` first request appeared on 10/15 Xray connections and 12/15 lite
connections; this measures reuse of harvested paths, not successful harvest commits. The bigbody
cancellation difference is 33.3 percentage points and timing median differences are 211--245 us:
this baseline does not meet the G2 criteria. No scheduling delays were added to correct it. Logs,
per-connection CSV, summary CSV and executed-binary hashes are local artifacts under
`build-g2-api/spider-baseline/resumed/` (ignored build directory). There is no after-worker result yet.

Sources live under `test/<dir>/`, and each suite builds as `build/test-<name>`. "Against Go" means
against vectors produced by running the reference's Go code (next section), not against a reading
of it.

TLS and REALITY:

| suite | what it proves |
|---|---|
| `hkdf` | the TLS 1.3 key schedule against RFC 8448, with the vectors extracted from the RFC text by `tools/vectors` |
| `record` | the record layer replayed through the whole RFC 8448 conversation, sequence numbers included |
| `handshake` | transcript hash and key exchange against the same trace |
| `msg` | handshake message parsing and Finished from the RFC 8448 flight; ServerHello and HelloRetryRequest verdicts in the reference's order |
| `hsframe` | handshake messages split across and packed into records come out the same, header included |
| `alert` | what goes on the wire when a handshake is refused, including the three cases where the reference sends nothing |
| `post` | records after the handshake (alerts, CCS, KeyUpdate, tickets, broken records), with expectations taken from the `nodealert` stand |
| `rawin` | how much the client asks the socket for, read by read, against uTLS's `rawInput` run in Go (`tools/rawin`) |
| `recopen` | records opened ahead on other threads give exactly what the loop's own decryption would, and nothing when an input differs |
| `aead` | AES-GCM (mbedTLS's AES-CTR, or on arm64 with AES and PMULL the client's own ARMv8 counter mode, plus the reference's GHASH) against mbedTLS GCM; ChaCha20-Poly1305 against mbedTLS; published vectors; record-sized lengths |
| `aead-mbedpoly` | the same suite with the Poly1305 the MIPS build uses |
| `x25519`, `x25519-ref10` | X25519 against RFC 7748 and against mbedTLS on hundreds of seeded pairs; the second build forces the 32-bit field the MIPS routers run |
| `ed25519`, `ed25519-ref10` | Ed25519 verification against RFC 8032 section 7.1, with bit flips, wrong keys, S at and above the group order, non-points; same two field layouts |
| `kex` | every key exchange the build can do derives the same secret on both sides and refuses off-curve and malformed shares |
| `mlkem` | ML-KEM-768 key generation and decapsulation against Go's `crypto/mlkem` |
| `reality` | the REALITY session-ID stamp against a transcription of Xray's client and the REALITY server (`tools/reality`) |
| `keys` | the base64url public key and hex short ID parsers, with encodings from outside the tree |
| `cert` | the certificate walk against certificates Go wrote, including a REALITY one whose signature field is an HMAC; the re-marshalled Certificate that goes into the transcript, against uTLS |
| `certverify` | CertificateVerify with real Go signatures over the RFC 8446 signing input, plus refusals |
| `chain` | the stranger-path chain check against a small PKI Go built: four ways to fail, told apart |
| `certcomp` | RFC 8879 decompression for zlib, brotli and zstd, and 570 cases against uTLS's own `decompressCert` |
| `x509go` | the port of Go 1.26.6 `x509.ParseCertificate`: verdict and error text for every certificate `tools/x509read` recorded, per word size |
| `tls12` | no shipped fingerprint table offers a TLS 1.2 suite this build cannot run (the handshakes themselves are in `test/tls12/run.sh`) |
| `hello` | GREASE rules no byte comparison can see: distinct values, the same group in supported_groups and key_share |
| `fphello` | the shipped fingerprint tables render the ClientHello byte for byte as the frozen uTLS captures, Firefox and Chrome |
| `fpt` | the fingerprint table loader on tables that are truncated, from another version, or ask for what the build cannot do |
| `vfilter` | the filter that decides when Vision may splice, including the cipher-suite membership check it once lacked |
| `vision` | Vision framing, "end" versus "direct", frames split across reads, and 240 streams against Xray's own `VisionReader` |
| `vless` | the VLESS request header byte for byte against a capture from Xray |
| `vresp` | the server's response header, which decides where the proxied stream starts |
| `xudp` | the xudp frame against the layout Xray's writer produces |
| `browser` | the Chrome version and Sec-CH-UA headers against Xray's `browser.go`, run for 127 CPUs (`tools/xraybrowser`) |
| `spider` | the shape of the spider's HTTP/2 request: preface, SETTINGS, window, one HEADERS, the field set |
| `spiderpaths` | which paths later spider requests take from the first page |
| `fetch` | the spider's fetch against a scripted site: redirects, windows, cancels, connection reuse, as the reference did on the stand |
| `gozip` | the port of Go's gzip reader, Read by Read, against Go (`tools/gozip`) |
| `gomap` | the emulation of Go's map walk order against Go's own maps (`tools/gomap`), within six standard errors per cell |
| `unorm` | NFC, the Bidi Rule and `idna.Lookup` against Go's x/text and x/net/idna, 100,000 generated strings plus full tables |

Hysteria2 and QUIC:

| suite | what it proves |
|---|---|
| `qhello` | the QUIC ClientHello against what the reference client sent to a quic-go server, both with and without the Chrome parrot |
| `qparams` | transport parameters against the reference client's values, as literal numbers |
| `qpin` | the certificate pin and CertificateVerify on the QUIC plane; misplaced handshake messages against Go's `crypto/tls` (`tools/misplaced`) |
| `qhp` | header protection against RFC 9001 appendix A |
| `qrx` | the receive buffer gives memory back when it drains, within the reference's 8 MiB window |
| `qtx` | the send queue's accounting: bytes ngtcp2 still points at are never reused |
| `qslot` | a stream handle finds its slot again after the slot was released and reused |
| `qdgram` | the largest datagram payload, computed as the reference computes it |
| `ngpatch` | each patch in `patches/ngtcp2/` against what quic-go computes on the same inputs (`tools/qgovec`) |
| `hybbr` | the port of hysteria's BBR (patch 0009) piece by piece, and NewReno before authentication (0018) against quic-go |
| `rxopen` | datagrams opened ahead on other threads give ngtcp2 exactly what its own callbacks would compute |
| `sendq` | the send queue's writer thread: the boundary, the wake, and a close that ends on a full socket |
| `h3` | QPACK both ways against nghttp3; the authentication request byte for byte against qpack v0.6.0 (`tools/qpackvec`); header order distribution against Go |
| `hy` | Hysteria2 framing at its boundaries: varints, lengths, oversized messages |
| `obfs` | Salamander against packets the vendored hysteria produced, and the salt generator against Go's `math/rand` |
| `gecko` | the Gecko frame against the reference's layout and the frames it drops |
| `reasm` | reassembly of proxied UDP from fragments in any order and number of copies |
| `udptab` | UDP session numbering and lookup with no ceiling, as the reference's map behaves |
| `hop` | port choice for hopping: uniform by rejection, and a failed random draw reported |
| `pad` | the padding's character distribution after moving to pooled randomness |
| `blake2b` | BLAKE2b against Go's implementation around the 128-byte block boundary |

Shared code and the program:

| suite | what it proves |
|---|---|
| `args` | command-line values that `atoi` would accept and should not |
| `say` | the one function that writes log lines: bounds, and one `write()` per line |
| `prefix` | HPACK/QPACK prefixed integers, including a continuation that never ends |
| `hpack` | our HPACK against nghttp2 in both directions; the encoder's dynamic table against x/net (`tools/hpackenc`, `tools/hpackdec`) |
| `h2frame` | the HTTP/2 preface and frame headers against nghttp2's |
| `xhttp` | the XHTTP stream-one request against lines from Xray's own HTTP/2 debug log |
| `events` | what an event and a read result mean, without a socket |
| `share` | one listener shared by workers wakes one waiting worker |
| `reader` | once a stage is removed from the reader thread it is never touched again |
| `seam` | the real `lc-tunnel` binary against a fake server: alerts on the wire, log lines under several workers, startup refusals, signal forwarding |

### The consistency checks

These run as part of `check-builds`. Most of them read a number or a token out of `vendor/` and fail
with both values named when this tree disagrees. They exist because a constant copied from upstream
is the one that goes stale.

| target | what it holds |
|---|---|
| `check-shell` | `package/files/lite-client.init` parses as POSIX shell |
| `check-rules` | the nft ruleset the init script renders: order, diverted ports, the server exemption, refusals (`test/rules`) |
| `check-tune` | the `tcp_mem` sizing the init script applies (`test/tune`) |
| `check-workers` | which `workers` values each plane accepts (`test/workers`) |
| `check-parrot` | the Chrome parrot is on by default, from the UCI option to a 1250-byte first datagram (`test/parrot`) |
| `check-quiet-lib` | nothing under `src/` outside `cmd/` prints on its own |
| `check-counters` | every statistics counter is both incremented and printed |
| `check-pend` | every path that opens a stream writes the request with what the client already sent |
| `check-request` | the wait for the client's first bytes is Xray's 500 ms |
| `check-retry` | dial retries are Xray's `retry.ExponentialBackoff(5, 200)` |
| `check-pool` | the pre-connect pool's lifetime, pause and default are Xray's |
| `check-rsa` | the RSA key size ceiling is uTLS's |
| `check-ack` | the write path runs inside the receive loop after quic-go's `maxPacketsToProcess` datagrams |
| `check-alerts` | every `LC_ALERT_*` number equals uTLS's for that name |
| `check-crypto` | the patched ngtcp2 accepts quic-go's 16 KiB of CRYPTO data per level |
| `check-qgo-reasons` | every CONNECTION_CLOSE reason the patches send is quic-go's own format string (`tools/qgoreasons`) |
| `check-refs` | every path to one of our files named in a comment exists |
| `check-names` | every `lc_`/`LC_` name a comment cites exists in the code |
| `check-cites` | every citation into `vendor/`, in all five forms the tree writes, lands inside its file, and the quoted code, named function and numbers are where it says (`tools/cites`) |
| `check-divergences` | every `DIVERGES: <id>` mark has a row in `DIVERGENCES.md` and every row has a mark; prints the count |
| `check-fingerprint` | `tools/fp` and Xray pin the same uTLS; the shipped Firefox and Chrome tables and `src/quic/chrome_hello.h` are exactly what that uTLS produces today |
| `check-vendor` | every vendored tree sits at the revision the pinned-revisions table records |
| `check-fetch` | `tools/vendor/fetch.sh` fetches every revision the pinned-revisions table records, so a pin moved in one place and not the other fails here and not on a fresh clone |
| `check-notices` | `THIRD_PARTY_NOTICES.md` is exactly what `tools/public/notices.sh` generates from the licences of the pinned trees |

`check-builds` then builds `lc-tunnel` with and without the Hysteria2 plane, confirms the version
stamp follows `LC_VERSION` without a clean build, confirms a change of compiler flags rebuilds the
affected objects, and runs `test/certcomp/live.sh`: an OpenSSL 3.5 server that really compresses its
certificate, with the server's own log read to prove it did.

Any of these can be run alone, for example `make check-cites`.

## 2. Vectors from the reference

The rule is that expected values come from the reference, by running it, and not from a person's
reading of it. A generator that reimplements what it checks produces vectors that agree with the
reimplementation. The tools under `tools/` follow three patterns.

**Plain Go programs, run by the gate.** Each writes a header into `build/gen/` that one or more suites
include. Because the image resolves their modules in advance, they run under `--network none`.

| tool | runs | used by |
|---|---|---|
| `mlkem` | Go's `crypto/mlkem` | `mlkem` |
| `cert`, `certverify`, `chain` | Go's `crypto/x509` and signers | `cert`, `certverify`, `chain` |
| `reality` | the REALITY stamp, transcribed statement by statement from Xray and the REALITY server | `reality` |
| `blake2b` | `golang.org/x/crypto/blake2b` | `blake2b` |
| `gomap` | Go's maps, walked | `gomap` |
| `gozip` | `compress/gzip` over a body that arrives in pieces | `gozip` |
| `hpackdec` | x/net's HPACK decoder | `hpack` |
| `qpackvec` | the qpack encoder quic-go's HTTP/3 client uses | `h3` |
| `spiderurl`, `redirurl` | `net/http` and x/net under Go 1.27, as Xray v26.9.9 builds its spider: URLs and redirects | `spider` |
| `spiderflow`, `spiderpool` | the same: window updates while reading a page, and connection reuse | `fetch` |
| `unitables` | GOROOT's own x/text and x/net/idna | `unorm` |

`tools/vectors` extracts every value of the RFC 8448 trace from the RFC's text rather than having
anyone type them. `tools/certcomp/gen.c` writes the brotli and zstd vectors with the encoders from
the vendored trees, because Go's standard library has neither.

**Generators laid into the reference's own packages.** Much of what matters is unexported.
`tools/qgovec/gen.sh` drops test files into the vendored quic-go packages through
`go test -overlay` and runs them there, so quic-go's internal loss detection, RTT estimator,
connection ID manager, flow controllers and congestion controller answer the same scripts that
`test/ngpatch` and `test/hybbr` replay on the patched ngtcp2. `vendor/` is never written; the overlay
changes only what the compiler reads. `tools/xraybrowser/gen.sh` does the same with Xray's
`browser.go`. The gate runs both.

**Frozen references, regenerated by hand.** Some generators need modules the offline gate cannot
fetch or a specific Go toolchain. Their output is committed next to the suite, and the tool's header
says how to regenerate it:

| tool | writes | what it runs |
|---|---|---|
| `x509read` | `test/x509go/reference.h` | Go 1.26.6 `x509.ParseCertificate`, as amd64 and as 386 (19,429 answers) |
| `rawin` | `test/rawin/reference.h` | uTLS's `readFromUntil` over a real `bytes.Buffer`, Go 1.27 (440 streams, 111,369 reads) |
| `visionread` | `test/vision/reference_read.h` | Xray's `VisionReader` |
| `certcompread` | `test/certcomp/reference_open.h` | uTLS's `decompressCert`, as a test inside a copy of uTLS |
| `certremarshal` | `test/cert/remarshal_vectors.h` | uTLS's Certificate message unmarshal and marshal |
| `misplaced` | `test/qpin/reference_misplaced.h` | Go 1.25.14 `crypto/tls` handshake message parsing |
| `salamander` | `test/obfs/reference_*.h` | the vendored hysteria's Salamander and Go's `math/rand` source |
| `hpackenc` | `test/hpack/reference_enc.h` | x/net's HPACK encoder across a connection |
| `fp` | `package/files/fingerprint.fpt`, `test/fphello/chrome.fpt`, `src/quic/chrome_hello.h` | uTLS's ClientHello, via `make fingerprint` (`check-fingerprint` fails if they drift) |

Two suites use a reference library directly instead of vectors: `test/h3` links nghttp3 and
`test/hpack` and `test/h2` link nghttp2, and what one side encodes the other must decode. Neither
library ends up in a shipped binary.

## 3. Cross-builds and qemu

`make check` is not green unless every program builds for both routers. `check-device` builds `all`
four times: mipsel (MT7621) and aarch64 (AX3000T), each with `HYSTERIA=0` and `HYSTERIA=1`, with
`-Werror` on. A missing toolchain or missing link stubs are a failure, not a skip, because a check
that quietly does not run turns "the router build was not tried" into a green gate. This target was
added after a green host run turned out to be compatible with a tree that did not build for the
router.

`check-arm64` builds `test-aead` statically for aarch64 and runs it under `qemu-aarch64 -cpu max`,
whose hardware capabilities include AES and PMULL. The host only ever takes the generic crypto paths,
so the run must report that it took the PMULL GHASH, the NEON ChaCha20 and Go's Poly1305, or it
fails. It also prints which AES counter mode ran (`aese` under qemu), though the gate does not
require that line. The `-ref10` and `-mbedpoly` suites above cover, on the host, the 32-bit field
and the Poly1305 that the MIPS build uses.

The image also carries `qemu-user` for other targets; `test-x509go` was run for mipsel under qemu
when the X.509 port was written, but that run is not part of the gate.

```sh
make check-device     # inside the image, after tc-fetch and the stubs
make check-arm64
```

## 4. Stands against the reference

The gate stops at formats, parsing and building. Whether bytes arrive through a real server, and
whether this client behaves like the reference client on the wire, needs the reference running. The
stands build it from `vendor/`. They are not part of `make check`, on purpose: building the
reference needs the Go module cache or the network, and a gate that fails for reasons other than the
code is a gate people stop reading.

Each stand's script header carries its recipe, its traps, and a control: a deliberate break that the
stand must catch. Run the control. A stand that cannot fail may be testing the loopback. Break the
client in a copy of the file, not with `git checkout`, which also takes uncommitted work with it.

### Hysteria2: `test/hystand/`

```sh
sh test/hystand/run.sh          # about 2.5 minutes, two containers on the lcnet network
```

`run.sh` builds the reference hysteria server, puts an echo target on the server's own loopback, and
pushes 32 MB through this client, checking every returned byte by its offset (`load/`), plus twenty
short connections and four concurrent streams. Then it tests the connection's life against the
reference's `reconnectableClientImpl`: idle close with a silent server, no dialling while nobody asks,
one attempt per request, reconnection when the server returns, surviving twenty seconds of ICMP
port-unreachable, and exit status 1 when the first connection cannot be made. The README lists the
controls for each.

Other scripts in the same directory reuse what `run.sh` built:

| script | question |
|---|---|
| `loss.sh` | the same transfer through the same impaired path (`impair/`, a relay that drops and delays in FIFO order), this client and the reference client alternately, three runs each |
| `closed.sh` | a stream the server ends before its answer: the request fails and the next one dials a new connection, as `ClosedError` does |
| `udpshape.sh` | how many sockets the server opens for one client's UDP (`seen/` reports source addresses back) |

### REALITY and Xray: `tools/vendorcap/` and `test/`

`tools/vendorcap/README.md` describes the capture tools and the stands. The ones that run both
clients:

| stand | what it compares |
|---|---|
| `qstand/run.sh` | a quic-go server with its own qlog: the first flight of the hysteria client and of this one, CRYPTO frames in arrival order, the parsed ClientHello including extension order, transport parameters |
| `wireshape/run.sh` | every write toward an Xray REALITY server, by size and timing, under strace, for both clients, uploads and downloads; reads two runs before calling a difference |
| `nodealert/run.sh` | the REALITY server with hooks that send any record after the handshake; what each client says back (52 scenarios) |
| `spiderlife/run.sh` | how long the connection lives when the server treats the client as a stranger |
| `spiderredir/run.sh` | what the spider sends when the cover site redirects (96 connections byte for byte against Xray) |
| `bbrcmp/run.sh` | hysteria's BBR package and patch 0009 driven through one script, compared number by number |

`vlesstrap` captures the plaintext an Xray client writes (VLESS header, Vision frames, xudp) and, in
relay mode between a real Xray client and server, sees a whole session including long padding.
`standsrv` and `udpbench` are measuring tools, not captures.

`qstand`, `bbrcmp` and the `test/hystand` scripts run from the repository root. `wireshape`,
`nodealert`, `spiderlife` and `spiderredir` run inside the build image with the tree mounted at
`/repo`. From the root of the repository:

```sh
docker run --rm -v "$PWD:/w" -w /w lc-build:local make build/lc-tunnel
docker run --rm -v "$PWD:/repo" lc-build:local sh /repo/tools/vendorcap/wireshape/run.sh
```

Three more stands live under `test/`:

| script | what it checks |
|---|---|
| `test/tls12/run.sh` | TLS 1.2 against Go's `crypto/tls`: every suite the Firefox hello offers, every key type and curve, tickets, OCSP, client certificate requests (34 handshakes) |
| `test/dialname/run.sh` | a REALITY server given by name, dialled by this client and by Xray side by side, when only one of the name's addresses answers |
| `test/udpwait/run.sh` | a UDP reply the LAN socket will not take yet (EAGAIN injected with `LD_PRELOAD`) must wait, not be dropped |

```sh
docker run --rm -v "$PWD:/w" -w /w lc-build:local sh test/tls12/run.sh
sh test/dialname/run.sh
sh test/udpwait/run.sh
```

`test/rig/server.json` and `test/donor/` are an Xray REALITY server and the site it fronts, built from
`vendor/Xray-core` and set up by hand when a change needs a server that can be broken and
instrumented. No keys are committed; `test/donor/README.md` says how to make them. `test/storm/` is
a load test of session lifetimes run against such a server with an AddressSanitizer build; the
sanitizer is the assertion.

`docker/Dockerfile.net` runs the transparent path (tproxy, marks, reply sockets) in network
namespaces. It needs a kernel with `nft_tproxy`, which the WSL2 kernel behind Docker Desktop lacks.

## Mutation testing

A test that passes on broken code proves nothing, and this tree has had several: a key-share check
that compared a pointer with itself; a gate that took the last line mentioning a constant, which
was a comment, and stayed green with the whole block deleted; an AEAD test at 512 bytes, the one
length that cannot fail; a test that pinned a defect as "correct, as Go does".

So each new suite, gate and stand scenario is run against deliberately broken copies of the code,
and the commit that adds it records how many of those mutants it caught. Some counts from September:
`test/x509go` 14 of 14, `test/rxopen` 10 of 10, `test/recopen` 11 of 11, `test/rawin` 6 of 6,
`test/tune` 17 of 17, the `redirurl` vectors 36 of 36, `tools/cites/claims` 15 of 15 code mutants and
9 of 10 citation mutants. `test/unorm` caught 98 of 120 and `test/gozip` 19 of 24; those commits
name the survivors as equivalent or unreachable.

There is no mutation harness in the gate. The practice is manual, with two rules learned the hard
way. Mutate a copy of the file and restore it by copying back, never with `git checkout`. And make
shell checks read their target through a variable (`test/workers` and `test/tune` do), so that a
mutated copy can be checked without touching the real file.

## 5. On the routers

### Full tunnel integration on the lab MT7621 (2026-10-30)

The current `lc-tunnel` snapshot, including the first-read EINTR correction,
ran as temporary MIPS binaries on the Mi Router 4A Gigabit, OpenWrt 24.10.8,
kernel 6.6.144, with the device's real mbedTLS 3.6.6 and zlib 1.3.1 libraries.
The installed client, firewall, routes and services were not replaced. Boot ID,
firewall/route hashes, AWG interface list and the web-service PID matched before
and after the complete matrix. The guarded client processes were stopped after
each phase.

Reference servers were built from pinned Xray `52a412d9` (Go 1.27.1) and Hysteria
`e1366b1` (Go 1.26.6), with disposable test identities in an isolated, bounded
container. Their source diffs against the pinned revisions were empty when
ignoring line endings. Before testing C, the checked backend was qualified
through the pinned Xray client. The stand explicitly permits only its own
loopback backend ports in Xray freedom finalRules; its default private-address
guard otherwise blackholes the test destination.

The matrix passed 105 asserted checkpoints, including startup and shutdown,
across REALITY/Vision and Hysteria2 with plain TCP and inner TLS 1.3:

- checked 2 MiB uploads and downloads, ten short connections and four concurrent
  duplex flows per phase;
- a slow receiver alongside a normally progressing independent connection,
  and a separately delayed server reader;
- deliberate data corruption rejected by the checker; complete transfers need
  the backend's receipt containing both SHA256 digests;
- native UDP echoes, including the Hysteria boundary for the fixed test target:
  4072 payload bytes plus 24 header bytes fit MaxUDPSize, 4073 are silently
  dropped, and a subsequent valid datagram still succeeds;
- interrupted transfers on reference-server restart, followed by fresh traffic;
- a silent Hysteria peer closed the active transfer after 30.3 seconds, followed
  by recovery after resume;
- an invalid VLESS UUID and invalid Hysteria authentication were rejected.

Hysteria's first request after losing a cached connection may fail while
invalidating that connection; the next request must succeed. This follows
`vendor/hysteria/core/client/reconnect.go::clientDo`, rather than an added
transparent retry. UDP's header-inclusive limit and silent oversize drop follow
`internal/protocol/proxy.go::UDPMessage.Serialize` and
`core/client/client.go::udpIOImpl.SendMessage` in the same pinned reference.

The workload reached the temporary listener through SSH direct-tcpip. A shared
duplex SSH transport stalled under concurrent load; separate SSH connections
per flow removed that stand failure without a client change. Python 3.10's
asyncio TLS reader also failed on slow peer closure; the final matrix used
Python 3.14.3. Earlier failed stand attempts remain in private evidence and are
not counted as client acceptance. This route establishes correctness and
lifecycle behavior, not a throughput comparison, fingerprint/G2 acceptance,
AX3000T execution or an extended soak. Fixtures: `test/devicestand/`.
Private evidence: `artifacts/lite-client/live-4a-20261030/`.

The subsequent bounded repetition also passed: 180 seconds of four-flow TLS
bursts per plane, plus warm-up and idle sampling, verified 644 additional duplex
connections. REALITY completed 84 batches plus warm-up: idle descriptors returned
to 28, with summed RSS 9160 -> 9924 KiB. Hysteria completed 75 batches plus
warm-up: descriptors returned to 14, RSS 3560 -> 3624 KiB. Process counts stayed
at five and one respectively. REALITY's native counters confirmed positive
Vision direct-copy and splice traffic. These are sampled observations over
bounded runs; allocator retention is included in RSS and an extended memory-leak
or performance claim is not established. The updated UDP helper also passed
after each repetition run, and router invariants still matched.

For concurrent REALITY spider G2, host/socketpair fixtures and QEMU are not a
substitute for hardware acceptance. Run the verified architecture-specific
snapshot on an AX3000T or the MT7621 lab router before claiming G2 closed.
Record the device/model/firmware, copied and executed binary hashes, real
CPU/RSS/worker lifecycle cost, backpressure/read-boundary results and fresh
paired cancellation/first-request measurements (three rounds, at least 15
connections/client/scenario). The checkpoints above are host measurements;
their new concurrent binaries have not yet passed this device acceptance.
Use an explicitly authorized isolated temporary test process; do not replace
the installed client, change router services/configuration, or count a check
of an older installed binary as verification of the new snapshot.

The two target boxes are an MT7621 (Xiaomi Mi Router 4A Gigabit: mipsel, no AES instructions,
118 MB of RAM) and an AX3000T (aarch64 Cortex-A53 with the crypto extensions). The toolchains are
OpenWrt 25.12.5's. What has been checked on them:

- the cross-built binaries run, against the router's own mbedTLS and zlib (`dl/mipslib` and
  `dl/a64lib` are link stubs only);
- `build/bench-aead` and `build/bench-kex`, cross-built, give the cipher and handshake costs quoted in
  the code and in [DESIGN.md](DESIGN.md) (AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, ML-KEM per
  operation); `test/bench/relay.c` is a crypto-free relay that shows what the box can move at all;
- `test-aead` cross-built for mipsel passes on the router, and on the AX3000T the PMULL GHASH agrees
  with mbedTLS's GCM 30 of 30;
- throughput against the reference clients on the same box, the same server and the same hour, run
  alternately (see [CONCURRENCY.md](../CONCURRENCY.md) and [HISTORY.md](HISTORY.md) for the numbers);
- handshake time with `lc-probe`, paired old and new binaries in alternation;
- long soaks read back through the SIGUSR1 statistics summary.

Traps recorded while measuring, each of which produced a confident wrong number at least once:

- run the two clients one after the other, not together. Some Hysteria2 servers keep one session per
  credential and close the older one;
- check that the binary on the router actually changed (compare its hash) and that no old process
  still holds the port;
- `/tmp` on OpenWrt is RAM, and binaries left there lower the memory everything else sees;
- paths over the internet vary by a factor of two within an hour. Alternate the builds, take three
  or more runs, and prefer CPU seconds per 100 MB over Mbit/s when comparing implementations;
- a benchmark built with test flags measures the test build. `bench-aead` builds each source with the
  flags the shipping binary uses, and fails loudly if a decryption does not verify.

### Startup diagnostic capture follow-up (2026-10-25)

The driver writes runtime `note()` messages through descriptor 1. The startup
failure fixture now captures stdout, flushing stdio before redirecting and
restoring it, instead of reading an unrelated stderr stream. Injected
`pthread_create` failures still return EAGAIN with stale EBADF in errno; the test
checks that the message names the failing task and the returned error.

The final focused fixture, both isolated mutations (late opening and stale errno),
the restored control, the full offline `make check` gate, ASAN/UBSAN and the
profiling fixture passed. Executed source hashes match the final source snapshot.
Private evidence: `artifacts/lite-client/diagnostics/opening-before-workers-fix-20261025`.

The three unit fixtures were then cross-built with the pinned OpenWrt 25.12.5
MIPS toolchain and run on the test 4A, OpenWrt 24.10.8 / kernel 6.6.144. All exited
0: fetch cleanup in 1 s, tunnel in 1 s, record-open pool in 32 s. One-second RSS
sampling observed peaks of 1272, 1484 and 1540 KiB respectively; minimum available
memory was 23560, 23252 and 12220 KiB. These are sampled observations, not precise
peak guarantees. The resource fixture used four sessions; production concurrency
was not changed. Boot ID and `awg0` were unchanged.

The native fixture build needs the real pinned zlib compressor, its include
path and explicit PIE test flags. The cross-link stubs used for production build
coverage do not export deflate. Earlier failed fixture build attempts are retained;
the successful build links real vendored zlib without changing vendor sources.
Device archive SHA-256:
`c670af2e084a551c0d3834ceae0f03fb32a6bab121f40edc43a6a66e56988787`.
The archive was retrieved and checksum-verified before removing the temporary
test directory. No production LiteClient was installed. These unit runs do not
establish VPN throughput or close the outstanding G2 wire-comparison criterion.

### Startup allocation-failure observation (2026-10-30)

The real-binary shared-cache startup fixture reproduced a test-controller race:
EOF on the diagnostic pipe could precede the child's reapable exit. Repeated
polling of that permanently readable pipe exhausted the old iteration counter
before `waitpid(WNOHANG)` observed the exit, despite the expected ENOMEM message.
The fixture now uses a monotonic three-second deadline and bounded polling
after EOF, retaining the exact required exit code, diagnostic and absence of
workers/listeners. Interrupted `waitpid` calls do not end the observation early.

The original fixture failed both two-worker allocation-failure cases. After the
controller correction, three consecutive `--cache-startup` runs passed all four
cases, including a busy listener and both normal-start controls. The daemon and
its protocol behavior were unchanged by this test correction.
