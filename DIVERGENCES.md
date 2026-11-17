# Where lite-client differs from its references

Reference migration, 2026-11-05: active code follows Xray v26.10.31 and
Go 1.27.3, including Vision Direct closure and HTTP/2 flow/header budgets.
These changes match the updated reference, rather than adding divergences.
Historical records below retain the reference versions measured at the time;
see docs/XRAY-COMPATIBILITY.md for the upgrade's evidence and remaining scope.

Owner clarification, 2026-11-05: flash is the size constraint; RAM measurements
are diagnostic without a MemAvailable floor or RSS cap in new native v4 plans.
Process/protocol correctness, complete monitoring and cleanup still apply.
Historical native v1/v2/v3 plans and failures keep their archived criteria.

Fresh ordinary host v4 and native v4 checkpoints pass on 5 November: each covers
24 phases/120 connections with complete identity, wire and cleanup validation.
The native Mi Router 4A run has zero first-request regression in all scenarios.
See docs/TESTING.md for diagnostic rates, prior rejected runs and scope. This
does not remove G2's documented implementation difference or declare a release.

Owner decision, 2026-11-03: G2's scheduler-dependent CANCEL and selected-path
frequencies are diagnostic, not acceptance thresholds. Preserve HTTP/2,
flow/cancellation/close correctness, cache ownership and resource checks; keep
the independent 100-us candidate latency-regression budget. The spider runtime
and its wire defaults are unchanged. G2 remains documented rather than requiring
a port of Go's scheduler. See [spider acceptance](docs/SPIDER-ACCEPTANCE.md).
New host v4/native v4 plans declare checkpoint scope; they do not expose a
G2Closed release flag. Historical measurements and failed criteria below retain
their original meaning and must use their retained analyzers.

## Historical checkpoint record

Owner decision, 2026-10-28: retain C speed/stability improvements without changing
protocol behavior. Matching Go's scheduler timings or frequencies of permitted
interleavings is not required. G2 remains a documented runtime difference;
validation must enforce wire/flow/cancellation/lifetime correctness rather than
add delays or transfer cleanup to the TLS owner to imitate scheduling. New v2
checkpoints cap candidate first-request regression at 100 us, retaining the rate
and protocol checks. Historical v1 absolute-gap failures below are unchanged.

Fresh native v2 evidence has zero latency regression and matching CANCEL rates
in all four scenarios. The closeafter selected-path rate remains outside its
retained check (C 10/15 versus Go 12/15), so the checkpoint is not marked passed.
Root requests remain valid after a harvest; direct commit/retention evidence is
needed before interpreting that selection difference as cache loss. Runtime
source and protocol behavior are unchanged by the acceptance-policy revision.

Latest G2 host checkpoint (2026-10-28) uses container-local journals: ordinary
C versus full Xray, three paired rounds, 15 connections per client/scenario.
First HEADERS absolute median gaps are 125/5/67/176 us for
bigbody/gzbody/latebig/closeafter; C is earlier except in gzbody. Bigbody CANCEL
is 7/15 versus 5/15 (13.3 points); closeafter harvest matches at 11/15.
G2 remains open under the unchanged 100-us/10-point limits. The preceding
Windows-bind-mounted run's apparent general C delay included synchronous log
latency. Source and identical executed-binary hashes are recorded in
docs/TESTING.md. These host checkpoints do not replace the frozen 136-block
experiment or establish native acceptance. Profiling changes no ordinary-build
protocol behavior; no scheduler delay or reference change was introduced.

The latest ordinary native checkpoint on 4A covers four scenarios in three
paired rounds with verified per-scenario role counterbalance (120 connections).
CANCEL matches per scenario; closeafter harvested paths match at 11/15. Bigbody
refund-before-HEADERS remains C 15/15 versus Go 0/15, and absolute first-HEADERS
median gaps are 3376--3668 us with C earlier. G2 remains open. This uses the same
binaries as the preceding limited native diagnostic, whose data remain separate.
Native cleanup boundary fixtures pass; no scheduler delay or priority is forced.

A subsequent separate 20-connection in-memory handoff trace places all ten C
first-DATA events between reset completion and stream removal/donec, before
Do's later notify/wait/next-request stages. Inspection now targets TLS-Write
completion to request/cleanup resumption. Active Go 1.27 transport/source identity
is verified; this diagnostic changes no ordinary runtime source and closes no G2 gate.

This is the one list. The project's rule is that the client behaves exactly like its references
(Xray with uTLS for REALITY, hysteria with quic-go and Go for Hysteria2), that any difference is a
defect, and that only the maintainer decides to step away from them. Everything known today to
differ is here, in plain words.

**How the list stays true.** Every row has an id, and the code carries a `DIVERGES: <id>` comment at
the very place where it differs. The gate (`make check`, target `check-divergences`) holds the two
together: a mark without a row, or a row without a mark, fails. Port the reference's behaviour and
remove the mark, and the gate will not let you forget the row; find a new difference and add the
mark and the row together. Every run of the gate prints how many there are, and of which kind.

**What is not here:**
- anything the reference does the same way, paying the same price (Hysteria2 under the Chrome parrot
  gets AES-GCM on an MT7621, as the reference does);
- anything outside the client: router scripts, the package build;
- raw findings of the automated citation audit. It writes them to VENDOR.md, VENDOR-REVERSE.md and
  COVERAGE.md; neither the tool nor those files are in the repository, most of its findings are
  false, and a finding becomes a row here only once the reference has confirmed it.

## Not yet ported: the reference already behaves differently, work in progress

A new finding becomes a row here, with its mark in the code.

| Id | What differs | Reference | This client |
|---|---|---|---|

## Not reproducible: Go's runtime, not the reference's code

| Id | What differs | Reference | This client |
|---|---|---|---|
| `G2` | Go's concurrent readLoop and request/Do goroutines in the REALITY spider | The socket readLoop collects TLS records while HTTP/2 RoundTrip, Do and request goroutines run independently. Their interleaving affects initial request/SETTINGS ordering and whether a completed body is read before cancellation. | The tunnel now runs independent Do and request/cleanup tasks, with loop-only socket/TLS ownership and stop/join of both. The loop resumes saved readLoop input through a protocol-only driver, never through private Do; transport EOF cannot overtake accepted reader input. Accepted buffered frames and the retained input feed now advance behind another task's Write until their own control/credit Write requires the ClientConn writer; their own opening/Flush still blocks them. Do now queues owned fields without reserving the actual writer; readLoop ACKs may acquire it before request task entry. Own cleanup excludes both queued and active request phases. Owned request fields are encoded only on the request task's first writer turn, after checking abort; an unsent cancelled request cannot mutate HPACK. DATA/Read/Close phases, pre-writer reset selection, owner-specific whole-Write completion and separate forget/final-writer phases are retained. Stream IDs are assigned by the independent request task after checking connection usability; other producer gates remain conservative; this is not a complete Go scheduler port. Ten new split-driver cases cover private-Do overlap, both END_STREAM/reset orders, stop/error, quiescent waits, invalid input and pre-encoding cancellation. Two earlier targeted mutants are rejected with a passing control. Thirteen further readLoop scenarios cover private Do, buffered/held input, real completion, stop/error, invalid DATA, duplicates and early EOF; real TLS backpressure tests require loop-owner resumption. Three new private mutants are rejected at intended assertions with both controls passing. The preceding readLoop checkpoint passes focused tests, ASan/UBSan and its offline gate (7489 ok lines). Twenty further post-padding driver scenarios cover later Read/Close owners, buffered tails, both stop/error boundaries, exact credit and non-writing cleanup. The preceding post-padding focused tests, ASan/UBSan and full offline gate pass (7998 ok lines); all 316 source-manifest entries match. Both targeted terminal/barrier and blocked-loop-call mutants are rejected with two passing controls; earlier harness failures are retained, not passes. The preceding supplemental TSan stopped before tests with unexpected memory mapping, exit 66; the current sanitizer result is recorded below. The preceding split snapshot's fixed 60-connection wire diagnostic observes candidate/reference CANCEL 14/20 vs 11/20; old binary/reference 4/10 vs 1/10. Small unequal groups and changing reference counts do not prove improvement, equivalence or causality. The preceding immutable binary's completed 136-block run failed bigbody: reference/C CANCEL 1040/3200 vs 2327/3200, gap +40.22 points, whole-block 95% interval +37.84 to +42.56, above the unchanged +10 limit. gzbody and latebig passed locally. The separate ten-buffer trace observed early cleanup and correct retention of a reset chosen before the writer wait; it did not prove the cause of the entire gap. Old 79-block prefixes, controls, trace and later diagnostic runs are separate, never pooled or subtracted for acceptance. The preceding readLoop binary's separate fixed 60-connection diagnostic completes with all guards and independent counts passing: C/reference CANCEL 16/20 vs 10/20; separate old-control rounds 8/10 vs 3/10. The +30-point descriptive candidate gap remains observable, without an improvement/regression or causal claim from small unequal retry groups. That diagnostic's binary SHA-256 is d8c7b04faa7c433255f5e33f93ad78076b4298771e221f5e74afe6856b9b8f0c, not the preceding post-padding candidate d0b38b3b6486494a21dbad7394b4eaed357672bb9654b1d23eda0f8c0cacbd67 or current queued-request candidate 924f9f70f7839dbac85dcd760a3c3393fb833e35fb947b7835a66c6cd466e3d5. Ten new queued-request cases and two real TLS/socket EAGAIN cases pass; both controls pass and three targeted driver/socket mutants fail intended assertions. Current focused tests, fetch/cleanup ASan/UBSan and clean full offline gate pass (8234 ok lines, not independent tests), with 316 manifest entries matching. One failed fixture-lifecycle gate is preserved, not a pass. A separate fixed 60-connection diagnostic for this current binary has its own frozen plan/evidence under diagnostics/request-acquisition-wire-20261007; all 60 connections, guards and independent counts pass. That preceding C/reference CANCEL was 15/20 versus 6/20; separate original-control rounds 8/10 versus 4/10. The +45-point descriptive candidate gap remains observable, without an improvement/regression, equivalence or causal claim from small unequal retry groups; neither individual-fix effects nor acceptance are established. This padded-DATA boundary proof does not establish the cause or disappearance of the unpadded bigbody gap; current wire/hardware acceptance remains unverified; the saved measurement checkpoint still selects the old binary. That checkpoint lacked fresh native CPU/RSS/lifecycle and stack-reservation preflight; bounded 4A results are recorded below. A source analysis of 21 October 2026 (no code change, no measurement, no causal claim) locates the reference's decision in writeRequest's wait for peerClosed against abort (transport.go:1195-1214), repeated by the cleanup gate (1308-1317), with peerClosed published under cc.mu alone (2381-2395) and the credit refund a separate cc.wmu section skipped when the refund is zero (2357-2367); a Close that broke the pipe first is the reference's own endStreamError path (2342-2347, 2369-2372). The 21 October snapshot's own amplification was that its readLoop parsed buffered frames only while no output was queued at all (fetch.c:3165) and publishes a DATA terminal phase only when that DATA has no credit left (fetch.c:3148-3152, 1663-1667, 1677-1680), although the per-frame gate that exempts DATA already exists (fetch.c:1981-1987, 2042-2048), while cleanup decides on abort alone (fetch.c:434, 924-926). Cancellations are separable in the source into the reference's own and this client's; no run has measured the split. G2 remains open. Those earlier checkpoints excluded router load, deployment and commit. The 22 October bounded 4A checks below do not establish traffic performance, B/C acceptance, SDK/APK/fortify or G5/G6 equivalence. Production AX3000T needs explicit bounded-test authority. No scheduling delays, blanket CANCEL suppression or relaxed limits. See `docs/TESTING.md` and `CONCURRENCY.md`. |
| `G3` | When the socket of a failed REALITY attempt closes | left to the garbage collector, closed on its next cycle. Measured 1 October with gctrace on Xray as a client (tools/vendorcap/gcstand): heap about 1 MB against Go's 4 MB floor, so a cycle every 3 MB allocated; idle, the forced cycle every 120 s; one a minute at 5–25 Mbit/s, one every 3 s with a new connection every 5 s, every 7–9 s while attempts fail | kept open and closed by a model of that cycle: a 3 MiB budget spent by bytes carried (one per 56) and by each handshake (210 KiB), a forced cycle every 120 s. Calibrated on the stand; Go's pacer is not ported, so the moment differs by up to one cycle. The nodealert stand now matches the reference in all 52 scenarios, FIN included |
| `G5` | Hysteria2 receive-window updates on a path with almost no delay | an `io.Copy` goroutine reads the stream in parallel with the connection loop, on another core, so updates go out evenly, a quarter of the window at a time | reads of 32 KiB and an update sent at once as the reference does, but what is read is what the connection has already taken in: on loopback the updates are sometimes bunched. At 20–60 ms they match (qstand). Reading after every batch of datagrams cost the MT7621 a seventh of its processor per byte. Writing to the client on a thread of its own, as the `io.Copy` goroutine does, was tried on 29 September on the MT7621: with one chunk 21.4 s per 100 MB against 19.7–20.0 and 10 % more processor, with two 20.4–22.3 against 19.6–22.8 and 7 % more; handing chunks between threads eats what freeing a core gains, so it was not taken |
| `G6` | How often Hysteria2 acknowledges | a reader goroutine queues packets as it reads them, the connection loop takes them until the queue is empty (at most 32) and acknowledges after each batch, so Go's scheduler sets the batch size. Measured 30 September on the LAN stand, 100 MB: AX3000T at 50 and 100 Mbit/s, one ACK per 3.3–3.6 and 9.6–9.8 packets, CPU-bound (~270 Mbit/s) one per 28–31; MT7621 CPU-bound one per 28–29; an x86 stand where the loop is not loaded, one per 14–17 | one thread reads the kernel's queue, up to 32 or until it is empty, and hands the data to clients itself: CPU-bound it is one ACK per 27–30, as the reference; when not CPU-bound it acknowledges more often, every 2.2–2.3 packets at 50 Mbit/s and 4.0–4.5 at 100 (AX3000T), 19–24 on the x86 stand, and spends about 12 % more processor than the reference. Tried and not taken: a reader thread with the reference's 256-entry queue (27 September, the queue overflowed on the MT7621); a model of the reference's queue by arrival time, with the loop busy while it opens a packet (30 September, 12–18 on the x86 stand but 3.2 on the AX3000T at 100 Mbit/s, further from the reference) |

### O5 task-result publication follows batching, 2026-10-28

Both workers publish their shared result once after draining runnable phases,
before done/eventfd publication, rather than release-storing every intermediate
rc=1. The TLS owner consumes these fields only for errors. The four-phase fixture
observes only the final result at eventfd write, and preserves the existing
quiescent/error/lifecycle wake counts. Prior source and three isolated mutations
fail the intended assertions; the restored source and native 4A fixture pass.
No cleanup continuation, writer boundary, wait predicate or wire setting changes.
Sanitizer scope, identities and validation are in docs/TESTING.md. No new G2 or
network performance result is claimed for this candidate.

### G2 queued Write / frame-dispatch arbitration, 2026-10-28

The TLS-owner trace finds bigbody DATA while reset is queued but not taken in
C 10/10; the subsequent socket calls succeed without EAGAIN. The owner can miss
a producer's new Write between its empty take and feed/read_step. cc_run now
checks queued runnable output under the protocol lock before every frame,
including a fresh feed's first frame. It retains input and returns to available
I/O, while preserving reads behind an in-flight Write. No producer wait, delay,
wire setting, Write boundary or cleanup ownership changes.
The regression fails on the preceding source and passes natively on 4A. Normal,
ASan/UBSan, encrypted socketpair and full offline cross-target checks pass;
three isolated mutations are rejected and the original source restored exactly.
In the fixed follow-up trace, all 10 C bigbody DATA dispatches follow reset
completion, but still precede redirected HEADERS, versus Go 0/10. The queue
window is corrected; post-completion scheduling and G2 acceptance remain open.
Binary identities, source hashes, controls and limitations are in docs/TESTING.md.

### O8 donec notification ownership, 2026-10-28

While Body.Close waits solely for donec, successful reset completion and stream
removal notify the request executor without advancing or waking Do. The final
cleanup check publishes donec and wakes Do. Terminal events and a pending
Body.Close-credit continuation retain their notifications. This follows
`transportResponseBody.Close`'s final select in pinned x/net transport.go;
no cleanup continuation runs inside TLS completion and DATA remains independent.
The reset/removal/donec fixture measures one Do notification instead of three.
Validation and limits are recorded in `docs/TESTING.md`; this does not close G2.
The subsequent matched 4A network diagnostic completes 160 connections and
still has bigbody credit-before-HEADERS in C 40/40 versus Go 1/40. The narrower
notification result does not establish network ordering equivalence or a
historical speedup. The old cleanup trace is not a trace of this candidate.
The new current-source trace observes bigbody DATA before redirected HEADERS
in C 10/10 versus Go 1/10. Nine C dispatches overlap the reset-send/completion
interval; those markers do not distinguish queued work from socket I/O.
The analyzer now distinguishes removal from the local redirected-HEADERS marker;
16 tests and five corrupted-evidence controls pass. The bounded instrumented
sample does not establish a scheduling fix or G2 acceptance.

### G2 feed-boundary I/O handoff, 2026-10-28

The split readLoop now returns accepted input to the TLS owner at a completed
frame when runnable output is queued. Buffered input has its own readiness
state; this does not invent a ClientConn writer dependency or wait for cleanup.
Native 4A fixtures, three isolated source mutations, sanitizers and the offline
cross-target gate verify retention, resumption, stop and failure. A fresh matched
160-connection diagnostic still observes bigbody refund-before-HEADERS in C
40/40 versus Go 0/40. Twelve corrupted-evidence controls are rejected. The
handoff does not establish reference scheduling equivalence; G2 remains open.
Binary/archive identities and measurement limits are in `docs/TESTING.md`.

### G2 native per-frame unlock follow-up, 2026-10-28

Releasing the state mutex between coalesced HTTP/2 frames permits Do/Body.Close
to run at the reference's frame boundary without a sleep or forced handoff.
The regression and native 4A fixture verify that opportunity, including stop and
readLoop-owned late-DATA credit. A subsequent matched native network diagnostic
still finds bigbody refund-before-redirected-HEADERS in 39/40 C versus 1/40 Go
connections. Both clients cancel all 40 bigbody streams and none of their 40 gzip
streams. The 160-connection run is bounded diagnostic evidence, not acceptance;
raw CPU/HWM observations do not establish a historical speedup. A later
40-connection instrumented native trace attributes C's ten bigbody credits to
DATA rejected by a still-found stream's broken pipe, with zero unread bytes
observed at Close. Go attributes nine to late DATA without an active stream and
one to Close with 5000 unread bytes. This narrows investigation to cleanup and
stream visibility relative to reset Flush, without proving the cause of the
uninstrumented scheduling distribution. Buffered traces agree with wire credit
multisets; instrumentation is not a performance or acceptance measurement.
No scheduler delay, fingerprint change or G2 threshold change is introduced.
The methods, resource checks and archive identities are in docs/TESTING.md.

### G2 reset completion and native TLS ownership, 2026-10-28

The next instrumented 40-connection checkpoint observes C's first bigbody DATA
handling during the pending reset Write in all ten connections, while Go handles
it after stream removal in all ten. A gap after completed Flush but before
forget is not observed in this sample. The producer ordering and reset counts
match complete traces and captured frames; this is not performance acceptance.

The single native TLS owner now services queued Writes before progressing
retained input. EAGAIN still allows independent readLoop progress, without a
global foreign-Write barrier or a wait for the producer's next turn. Writes
queued before a terminal read result retain their actual completion contract.
Socketpair tests, two isolated mutations, focused sanitizers, the full offline
gate and the final native 4A fixture pass. The ordinary 40-connection follow-up
still observes bigbody credit-before-redirected-HEADERS at 10/10 C versus 1/10 Go.
This validates the I/O servicing change without claiming that it fixes G2 or
improves historical timing. The remaining feed-boundary question, source hashes
and evidence identities are recorded in docs/TESTING.md.

### G2 request-owned stream admission, 2026-10-26

Do now queues owned fields with ID zero; the request task assigns the stream
ID before a separate encoding continuation. This follows pinned x/net
`ClientConn.internalRoundTrip`, `clientStream.writeRequest` and
`ClientConn.addStreamLocked` in `vendor/x-net/http2/transport.go`. Its own
opening Flush precedes admission; an unrelated cc.wmu owner does not block it.
No scheduling sleep, altered cancellation predicate or new fallback is added.

The preceding early assignment made an unexecuted task visible to readLoop.
An isolated test of the pinned Go 1.27.1 internal HTTP/2 implementation confirms
that DATA for the unassigned ID instead returns ConnectionError(PROTOCOL).
Driver tests cover that boundary, ignored reset, stop and changed peer
concurrency, plus existing abort, redirect and real socket-backpressure cases.
The full offline gate, focused sanitizers and bounded native MIPS fixtures on
4A pass. A fresh fixed 120-connection host checkpoint still observes bigbody
C/reference CANCEL 9/15 versus 5/15, and first HEADERS 660/548 us. The descriptive
+26.67-point CANCEL gap and three scenarios' absolute median timing gaps exceed
the unchanged limits. G2 and hardware traffic acceptance remain open. Full
validation, methods, identities and limits belong in `docs/TESTING.md`.

### G2 completed HTTP executors, 2026-10-26

Split Do and request executors now return independently of the retained
TLS/readLoop, following Xray `reality.go::UClient` and x/net
`clientStream.doRequest/cleanupWriteRequest`. Request retirement waits for all
owned producers, actual Write completions and cleanup; a parked request waiter
is notified when Do ends. Completed native threads are joined by the event loop,
without stopping fetch or changing protocol frames. Late PING, forgotten-stream
DATA and deferred EOF remain owned by readLoop. Six lifecycle mutations,
focused sanitizers, the full offline gate and native MIPS/AArch64 fixtures pass.
The worker-cache prototype remains unadopted. This is a reference-lifetime
correction; G2 timing/CANCEL acceptance remains open. Exact paired results,
native limits and retained failed attempts are recorded in docs/TESTING.md.

### G2 Do-first native startup, 2026-10-26

After the opening Write, Do now starts before the idle request executor (O6),
matching the reference's already executing Do/RoundTrip launching doRequest.
The executor's existing readiness predicate retains work published before its
creation. Deterministic tests hold that creation until Do publishes a request,
then cover normal progress and rollback when creation fails. The preceding
request-first source fails the intended assertion with a passing restored
control. Offline builds, focused sanitizers and native MIPS unit fixtures pass.

Private profiling observes Do entry medians of 179.7/99.6 us after creation
begins, but the fresh final 120-connection host checkpoint still has bigbody
C/ref CANCEL 10/7 of 15 and first HEADERS 576/341 us. Gzip HEADERS are 430/279 us.
These exceed the unchanged checkpoint criteria, so G2 stays open. Profiling and
small dependent retry groups do not establish a VPN speed gain or hardware
traffic acceptance; full methods and controls belong in `docs/TESTING.md`.

### G2 opening before worker creation, 2026-10-25

The initial HTTP/2 Write is now submitted before either pthread is created,
following `newClientConn`'s Flush-before-readLoop ordering. The real encrypted
socketpair fixture observes peer bytes at the first pthread creation; EAGAIN,
early input and stop still respect matching opening completion. Startup failures
identify their stage/fd and the pthread return code. A fixed 80-connection
diagnosis observes C first-read medians of 222.5 us before and 68 us after;
first HEADERS are 603.5/555.5 us, with reference controls 316/283.5 us. All four
C/reference groups have 10/20 CANCELs. These dependent groups do not close G2;
first HEADERS still lag, and the wire snapshot precedes the final error-log
additions. Full validation and native fixture evidence belong in docs/TESTING.md.

### G2 private gzip work and cold initialization, 2026-10-26

Gzip construction/inflation no longer hold the fetch protocol mutex. Its source
alone acquires pipe/flow state and owns returned bytes until the next source
Read, preserving them across concurrent pipe compaction or growth. The pinned
reference's `gzipReader.Read`/`acquire`/`release` and
`transportResponseBody.Read` run that work outside ClientConn locks. Stop and
failure interrupt protocol work without waiting for inflation; accepted clean
EOF still precedes loss handling and harvest. A separate cold-constructor race
in the shared fixed-Huffman table is corrected with `pthread_once`, matching
Go 1.27 `compress/flate.fixedHuffmanDecoderInit` and its `fixedOnce.Do`.

The old constructor fails ThreadSanitizer with a fixed-table data race. Three
isolated mutants (locked inflation, aliased pipe bytes, source Read after stop)
fail intended assertions with passing restored controls. Full offline builds,
focused ASan/UBSan/TSan and four native MIPS unit fixtures pass. These correct
reference boundaries and a race; they do not close G2 or establish a VPN speed
gain. Fresh wire results and limitations belong in `docs/TESTING.md`.

### G2 paired event diagnosis, 2026-10-23

A separate fixed 40-connection trace/plain comparison instruments both the
current C candidate and Go 1.27's executing internal HTTP/2 transport. All seven
traced C cancellations close the body before DATA dispatch; two already have
decrypted input at the pre-lock feed call. Traced Go has three cancellations,
only one before DATA dispatch. Neither cleanup cancels an observed clean peer
end. This narrows the ordering investigation without proving a mutex defect,
the cause of the full gap or acceptance. Product source is unchanged; no delay,
CANCEL suppression or relaxed threshold is introduced. See `docs/TESTING.md`
for exact counts, controls, instrumentation effects and evidence. G2 stays open.

### G2 reader-boundary update, 2026-10-22

The current readLoop resumes accepted frames and a retained feed behind another
task's queued Write. Only its own opening/Flush or a frame's actual ClientConn
writer dependency blocks it. It does not complete, reorder or cancel that other
Write. Sixteen deterministic cases cover buffered/held END_STREAM, a subsequent
PING, stop/error and cancellation selected before the reader's turn. A real
TLS/socket-EAGAIN fixture checks the exact credit Write without spurious CANCEL.
The row above retains the earlier checkpoints and their measurements. This fixes
a proven boundary; it does not by itself close G2 or replace wire/hardware acceptance.
The current focused suites pass ASan/UBSan and TSan; the full offline cross-build
gate passes. The bounded 4A fixtures pass with four spider sessions and the real
parallel record-opening pools, without changing its active AWG configuration.
The fixed short wire comparison still observes candidate/reference CANCEL
11/20 versus 7/20, with original-control/reference groups kept separate at
8/10 versus 4/10. These small unequal groups are descriptive, not acceptance.
The detailed row retains historical checkpoint descriptions; the current
reader contract and measured verification are in CONCURRENCY.md and docs/TESTING.md.

A subsequent socket-readiness regression confirmed that temporary `node_fill`
results could be mistaken for EOF. Its fix preserves EAGAIN and actual EOF as
distinct outcomes and passes host sanitizers, the full cross-build gate and the
bounded native 4A fixtures. The first 136-block run of the reader-boundary
snapshot was stopped for this source finding, before examining its partial
cancellation outcomes. It is not acceptance evidence and contributes no blocks
to a later experiment. See the separate readiness entry in docs/TESTING.md.

### G2 cross-ClientConn request writer, 2026-10-22

A submitted request now acquires its own ClientConn's writer even while another
ClientConn holds an unfinished TLS Write. This follows the pinned x/net
`encodeAndWriteHeaders` acquisition in `http2/transport.go:1221`; the TLS queue
still serializes whole Writes. Own opening/ACK/Flush waits, cancellation before
HPACK encoding, separate completion ids, stop and sticky per-ClientConn errors
are retained. Eight public-driver redirect cases cover those boundaries;
two encrypted socketpair cases verify actual ACK/HEADERS completion order and
stop under socket EAGAIN. The preceding code fails the intended acquisition
assertion. The final offline gate, focused ASan/UBSan/TSan suites and three
bounded native 4A suites pass; see `docs/TESTING.md` for evidence and limits.
This is a boundary correction, not a measured speed gain or G2
acceptance. The active 136-block experiment retains its preceding frozen binary.

### G2 body-credit writer acquisition, 2026-10-22

Read and Close now acquire only their own ClientConn's writer for flow-credit
return, as `transportResponseBody.Read` and `Close` do in pinned x/net
`http2/transport.go:2173-2263`. Foreign socket output no longer stands in for
cc.wmu; an empty queue cannot bypass an owned writer either. Saved Read bytes,
credit accounting and matching Flush completion remain separate phases.
Eight public redirect-driver cases cover Read/Close behind an older ClientConn's
PING Flush, exact queued WINDOW_UPDATE ownership, stop and both Write failures.
The preceding source and a separate Close-only global-barrier mutant fail the
intended acquisition assertion. The final offline gate, focused ASan/UBSan/TSan
and bounded native 4A suites pass. A racy test backpressure setup was corrected
without increasing its timeout; the failed run is retained. See `docs/TESTING.md`
for verification and limits. This does not close G2 or claim a speed gain;
the active fixed measurement keeps its preceding frozen binary.

### G2 initial RoundTrip admission, 2026-10-23

The first RoundTrip can now admit its request after its opening Flush even while
a later readLoop ACK owns cc.wmu. This follows `internalRoundTrip` spawning
`doRequest`, stream allocation in `writeRequest`, and the subsequent writer
acquisition in `encodeAndWriteHeaders` in pinned x/net `http2/transport.go`
(:966, :1120, :1221). Admission owns copied fields, not HPACK or the writer.
Only the independent request task encodes after the ACK actually completes.
Eight public-driver cases and two TLS/socket-EAGAIN cases cover this boundary;
both reject the preceding source at their intended admission assertions.
Later Do attempts retain their existing gating. No scheduling delay, altered
wire format, speed claim or G2 acceptance follows from this correction.
The existing full measurement retains its preceding frozen binary and inputs.
The full offline gate, focused ASan/UBSan/TSan suites and bounded native 4A
fixtures pass. All 316 source-manifest entries match, and the clean native
build hashes match the binaries actually executed on the device.

### G2 redirect continuation admission, 2026-10-23

After Body.Close and cleanup complete, Do now admits the next redirect request
without waiting for an unrelated socket Flush. This matches Go 1.27 `Client.do`
in `src/net/http/client.go:726-746` and the separate `internalRoundTrip` /
`encodeAndWriteHeaders` phases in pinned x/net `http2/transport.go:966, :1221`.
HPACK encoding still waits for the request's own ClientConn writer; whole Writes
retain their original completion identities and socket order. Eight deterministic
driver cases and two actual TLS/socket-EAGAIN cases cover this boundary. This
does not remove the separate backoff/retry gating or establish a speed gain.
The full offline cross-build gate, focused ASan/UBSan/TSan suites and bounded
native 4A cleanup/tunnel/parallel record-opening tests pass. Both preceding-source
driver and socket runs fail at their intended admission assertions. Source and
binary identities, resource samples and remaining limits are in `docs/TESTING.md`.
The current binary's separate fixed 80-connection diagnostic completes with all
guards and independent counts passing. C/Go CANCEL is 14/20 versus 2/20; the
independent Go-B/Go-A control is 8/20 versus 12/20. These small dependent retry
groups do not establish equivalence, performance or an individual-fix effect.
The current cancellation gap remains observable and G2 stays open.

The preceding frozen binary's 136-block comparison has completed. It does not
pass G2: bigbody C/reference CANCEL is 2112/3200 versus 911/3200, a +37.53-point
gap (whole-block marginal 95% interval +35.47 to +39.62), above the unchanged
+10-point limit. First-request median gaps also fail in bigbody and gzbody.
The independent Go/Go control passes. That candidate predates the later writer
and admission corrections; its results are not evidence for the current binary.
The bounded source correction and the full measurement remain separate evidence.

### G2 SETTINGS ACK writer boundary, 2026-10-24

The readLoop now acquires its own ClientConn writer for SETTINGS ACK too,
matching pinned x/net's `processSettings` (`http2/transport.go:2455-2471`)
and the Go 1.27 internal transport used by the reference. PING ACK still
requires no writer. Parser/order errors are rejected before that acquisition;
setting validity is checked afterward. Whole-Write identities, socket ownership,
request tasks and parallel record opening are retained. The preceding source
is rejected by driver and real TLS/EAGAIN cases. The intermediate implementation
that acquired the writer before parsing fails the malformed-frame assertion too.
See docs/TESTING.md for verification and limits.
This boundary correction does not close the existing cancellation, wire or
hardware acceptance gaps and introduces no scheduling delay or CANCEL suppression.

### G2 kernel-readiness diagnosis, 2026-10-24

A separate fixed 40-connection experiment instruments Body.Close socket queues
in both clients and C's input-owner events. All guards and independent wire
counts pass. Traced C/Go CANCEL is 8/10 versus 3/10; plain is 8/10 versus 6/10.
Three C cancellations and one Go cancellation have queued kernel bytes at Close.
All eight traced C cancellations precede DATA dispatch; one has plaintext waiting
to enter feed. No combined READ|WRITE event occurs before Close in this sample,
so it does not establish write-first combined-event dispatch as the cause.
Kernel bytes are encrypted, not proof of a complete frame; sampling perturbs the
two scheduling models differently. Observer and sanitizer checks, identities,
the analyzer syntax correction and limits are recorded in docs/TESTING.md.
Production code and the saved long-experiment checkpoint are unchanged. No
equivalence, performance, individual-fix effect, hardware pass or G2 closure is
claimed, and no historical data is pooled.

### G2 combined socket readiness, 2026-10-25

The event loop now preserves both READ and WRITE in a combined spider socket
event. A real TLS/socketpair regression blocks a PING ACK at EAGAIN, then checks
the queued response is dispatched when that Flush completes. Its own writer
barrier, repeated readiness, EOF and exact encrypted ACK are checked separately.
The preceding write-first selection fails the intended assertion in an isolated
source copy. The fetch/cleanup/socket suites pass normally and under ASan/UBSan
and TSan. The full offline cross-build/QEMU gate passes; all 316 source-manifest
entries match. Fresh MIPS fixture binaries build, without execution on the memory-low
4A. This is a boundary correction, not a measured change in the cancellation gap:
the preceding kernel-readiness diagnosis observed no combined event before Close.
G2 and hardware traffic acceptance remain open. See `docs/TESTING.md`.

### G2 native fixtures and matched current candidate, 2026-10-25

The combined-readiness candidate now passes bounded native MT7621 cleanup,
real TLS/socketpair and parallel record-opening suites. Executed binary hashes
match the verified source; the corrected controller captures and compares boot
identity and AWG interfaces itself. The four-session fixture returns to its
1608 KiB baseline after joining every worker. Each of the three ciphers opens
2700 checked records, with actual thread answers. These are native fixture
results, not acceptance of router traffic or a speed gain.

A separate matched 80-connection host diagnosis observes current C/reference
CANCEL at 14/20 versus 4/20; the write-first predecessor gives 15/20 versus
10/20 in its reference control. All input/source and executed-binary guards pass.
The control varies, retry connections are dependent, and this is not an
individual-fix effect estimate. G2 remains open. The preceding long measurement
and frozen checkpoint are preserved; details and limits are in docs/TESTING.md.

## Maintainer's decision: a deliberate step away

| Id | What differs | Reference | This client |
|---|---|---|---|
| `O1` | REALITY on several cores | one program; Go's scheduler moves work between cores as it runs, on as many cores as there are | one process per core, at most eight; a connection stays in the process that accepted it. Each worker requires parent-death protection tied to the original supervisor PID, including when a non-init subreaper adopts it. Atomic signal waiting and per-slot deadlines keep diagnostics responsive while retrying failed forks and short crashes at the existing procd interval. Startup restores usable SIGTERM handling before listeners/forks even if the launcher suppressed it. The 52-assertion lifecycle/signal/retry fixture and 57-assertion real-binary termination fixture, mutations and native MIPS results are recorded in docs/TESTING.md. |
| `O2` | Hysteria2: packets from the server opened on several cores | quic-go removes header protection and AEAD in the connection goroutine, Salamander in the read goroutine | a batch of 32 datagrams is opened ahead by threads (cores − 1) while the loop hands ngtcp2 the previous one; empty batches wake nobody and a smaller batch notifies at most one worker per datagram, while full batches retain the entire pool; ngtcp2 takes a ready answer only when every input matches, and nothing changes on the wire (decided 29 September, notification refinement 26 October, CONCURRENCY.md and docs/TESTING.md) |
| `O3` | REALITY: records from the server opened on several cores | uTLS opens each record in the goroutine that reads the connection: one stream, one core | whole records that have been read (up to 16) are opened ahead by threads (cores − 1) with their own copy of the key while the loop hands the previous one to the client; an answer is taken only when record, length, sequence number, algorithm, key and IV all match and the record opened, otherwise the loop opens it itself; on an open tunnel the socket is read ahead, up to four records at a time, while a model of uTLS's rawInput (tls/rawin.h) runs alongside and counts what the reference would not yet have read; closing with such a remainder is a RST (SO_LINGER 0), as the reference's close is with unread bytes in its socket; the handshake, fallbacks, the spider and a single processor read in the reference's pieces; nothing changes on the wire (decided 29 September, read-ahead 30 September, CONCURRENCY.md) |
| `O4` | x86-64 GHASH implementation | Go uses interleaved AES-NI/PCLMUL assembly when AES, PCLMULQDQ, SSE4.1 and SSSE3 are present. | The same CPU condition selects a one-block C intrinsics multiply/reduction derived from pinned mbedTLS aesni.c. Padding and authentication bytes match mbedTLS; no cipher preference, TLS framing, retries or close decisions change. MIPS/ARM implementations are unchanged. The x86 host cost measurement and its limits are recorded in docs/TESTING.md; G2 remains open. |
| `O9` | REALITY path-choice workspace | `reality.go::getPathLocked` advances the persistent Go map iterator to a selected rank. | C rebuilds the same layout from cached hashes and selects one key without an N-index output array. Complete preceding tables are skipped by their live counts. Cached hashes, selected ranks and entropy draws remain unchanged. Full header walks retain their original traversal and inlined construction/cleanup. Exact Go vectors, allocation-failure checks and matched native CPU measurements are recorded in docs/TESTING.md; this is not network throughput or G2 acceptance. |
| `O5` | REALITY spider event-loop notifications | Xray's x/net HTTP/2 tasks run independently on Go's scheduler (`internalRoundTrip`, `clientStream.doRequest`, `ClientConn.readLoop`). | The two POSIX workers finish their runnable continuations before one eventfd notification at a real wait, completion or error. The TLS owner alone submits and acknowledges whole Writes. A four-phase task fixture measures one quiescent/error notification instead of four; normal task completion additionally publishes its own lifecycle wake so the native thread can be joined without stopping readLoop. This is a notification-count result, not a VPN speed measurement. Matched wire and device evidence belongs in docs/TESTING.md; G2 remains open. |
| `O6` | REALITY spider native task startup | Go already executes Do/RoundTrip when `internalRoundTrip` launches `cs.doRequest` (`vendor/x-net/http2/transport.go:948-966`). | After submitting the opening Write, create Do before the request executor, allowing request publication to overlap the second native creation. The executor observes queued work through its existing readiness predicate, even when publication precedes creation. Both workers retain their ownership and stop/join contracts; failure of either creation ends startup with a stage-specific log. No pool, scheduling delay or wire change is introduced. The paired startup profile and its measurement limits belong in docs/TESTING.md; G2 remains open. |
| `O7` | REALITY spider output-buffer ownership | `ClientConn.writeHeaders` ends with `bw.Flush` (`vendor/x-net/http2/transport.go`); each Write completes at the connection, before its writer continues. | The last queued Write transfers its existing allocation to the TLS owner, avoiding one allocation and one payload copy. A prefix with later queued Writes is still copied. Every boundary, owner-specific completion and socket failure remains explicit; appending new output cannot reuse detached storage. There is no retained buffer pool. Allocation/ownership fixtures and matched wire evidence belong in docs/TESTING.md; G2 remains open. |
| `O8` | REALITY spider task notifications | `internalRoundTrip`, `clientStream.writeRequest` and the body pipe use separate response, abort and body-read notifications (`vendor/x-net/http2/transport.go`, `vendor/x-net/http2/pipe.go`). | Do and the request executor wait on separate POSIX conditions. Input notifies the request executor only when its existing readiness or completion predicate is true; stop, connection failure and OOM wake both channels. Normal Do completion wakes a parked request executor, which retires only after all request producers and cleanup have finished. Do's quiescent continuation does not advance its input generation. Successful request-task stream admission likewise leaves Do asleep: addStreamLocked does not publish a response, abort or donec event. The request's next writer turn stays runnable, and encoding, rejection, cleanup and terminal errors retain their notifications. Six deterministic outcomes and three isolated mutations cover the admission boundary. A real blocked-wait fixture checks work/stop/failure without a scheduling sleep; initialization failure unwinds both channels. No new cancellation decision or Write boundary is added. Measurement and validation belong in docs/TESTING.md; G2 remains open. |
