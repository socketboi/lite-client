# Concurrency: ownership, current contracts and measurement history

Current acceptance policy (owner decision, 2026-11-03): preserve observable
protocol and lifetime correctness; CANCEL/path-rate agreement with Go is not
required. Run `make check-spider-behavior`; see
[SPIDER-ACCEPTANCE.md](docs/SPIDER-ACCEPTANCE.md) for the gate and new checkpoint
formats. Historical measurements below retain their frozen criteria and results.
This policy changes no runtime scheduling, fingerprint, retries or spider traffic.

Dated historical evidence references omit internal run suffixes; full paths
remain in private records.

The controlled response-close oracle now matches C production drivers against
the unmodified active Go 1.27.1 transport for END before Close, Close before END,
and END during an already-selected reset Write. CANCEL outcomes are 0/1/1 and
each case refunds exactly 5000 connection bytes, with no stream refund or PING.
Close waits for actual Write and cleanup completion. The new cases run in the
ordinary cleanup suite; `make check-spider-close` also checks the real Go oracle.
Race, sanitizer, isolated mutation and MIPS/AArch64 QEMU results are recorded in
docs/TESTING.md. These forced orders neither explain the ordinary bigbody rate
gap nor close G2; this increment makes no runtime or scheduling change.

The current-runtime ordinary host v3 checkpoint completes 120 captures with all
client/stand identities, liveness and stop results checked. bigbody CANCEL is
C 9/15 versus Go 3/15, above the unchanged rate limit; the other three scenarios
meet local criteria and first-HEADERS regression is zero throughout. The host
analyzer now hashes actual stand inputs and requires complete process receipts.
Native/historical formats and comparison thresholds remain unchanged; G2 stays
open. See docs/TESTING.md for method, provenance and limits.

REALITY path choice now selects one iterator position without an N-index output
array. Complete preceding tables are skipped by their live counts; hashes, rank
bounds, entropy draws and the existing lock scope stay intact. The 206-assertion
Go-oracle/allocation fixture passes on host and native MIPS, with sanitizer and
mutation checks. Matched 4A CPU measurements and their limits are recorded in
docs/TESTING.md. This O9 workspace optimization does not close G2.

The tunnel resets inherited SIGTERM ignoring and unblocks SIGTERM before opening
listeners or forking. The supervisor and workers therefore retain the normal
signal termination behavior even if the launcher suppressed TERM before exec;
parent-death delivery also releases worker listeners. Setup errors fail startup
explicitly. This is an O1 process-lifetime correction; it adds no protocol or
shutdown policy. Real-binary inherited-signal checks are recorded in docs/TESTING.md.

Supervisor signal handling now uses an atomic pselect wait with managed signals
blocked during inspection. Missing slots retry on individual deadlines instead
of waiting for a healthy sibling to exit. Short-crash/fork-failure backoff follows
the existing five-second procd interval while diagnostics remain responsive;
signals do not accelerate retries. Workers restore their inherited signal state.
All 52 lifecycle/signal/retry assertions pass on host and native MIPS; four
mutations are rejected and ASan/UBSan passes. This O1 management correction does
not change worker count, protocol bytes or G2 criteria. Details are in docs/TESTING.md.

The process supervisor now binds each worker to its original parent PID instead
of assuming an orphan's adopter is PID 1. A denied parent-death signal is an
explicit startup failure. Controlled real-fork/subreaper tests cover the lost
parent before prctl, normal SIGTERM delivery and denied registration; all 19
assertions pass on the host and native MIPS. Both targeted mutations fail and
ASan/UBSan passes. This corrects worker lifetime within O1; it adds no scheduling
delay, process topology or wire behavior. Details are in docs/TESTING.md.

REALITY startup now requires the shared path cache before binding listeners or
forking multiple workers. Allocation/initialization failure returns status 1 with
its diagnostic rather than running independent per-worker caches. Real-binary
resource-limit tests exercise both free/busy ports and positive controls; both
continuation/ordering mutations fail. The final full gate and all sixteen startup
checks on native MIPS pass. Hysteria does not initialize the unused
REALITY cache. See docs/TESTING.md for the separate startup checkpoint.

Shared path-cache recovery now rebuilds lookup metadata from committed keys after
a worker dies holding its robust mutex. Table/mask and uncommitted-slot failures
are reproduced on the earlier source; six additional lifecycle/error checks pass
after repair. Publication uses release stores so initialized allocations precede
their offsets/counts on MIPS32 too. Stored hashes and draw behavior stay unchanged.
Host sanitizers, three isolated mutations, the full offline gate and native 4A retention checks pass;
QEMU lacks the required process-shared robust mutex. This is a cache-lifetime
correction, not a new G2 acceptance result. See docs/TESTING.md for identities.

## Current REALITY spider ownership contract — 2026-10-28

Owner decision on this date: preserve faster/stabler C execution while keeping
protocol behavior unchanged. Go scheduler timing and empirical frequency of its
legal interleavings need not be imitated. Checkpoint v2 limits candidate latency
regression to 100 us, reports absolute/signed differences separately, and retains
all protocol/rate/identity/guard checks. The following v1 measurements retain
their original absolute-gap conclusions; they are not retroactively reclassified.
The request/cleanup task stays independent of the TLS owner, with exact Write
completion, concurrent read progress, failure and KeyUpdate semantics preserved.

The fresh native v2 run uses unchanged runtime binaries: all four first-HEADERS
regressions are zero and CANCEL matches per scenario. Three scenarios meet the
checkpoint limits. Closeafter selected harvested paths are C 10/15 versus Go
12/15, outside the retained 10-point rate check. That metric counts selected
paths, not commits: / remains legal after harvest, and one C round selects it
after two /h0 requests. The result stays failed under that unchanged rate check;
no forced path choice, delay or TLS-ownership rewrite is used
to fit the sample. G2 remains a validation scope, not a mandate to copy Go's
internal scheduler. See docs/TESTING.md for the exact policy and raw outcomes.

Separate direct retention fixtures and paired host/native traces now observe
exact membership. In the fresh twenty-connection 4A diagnostic, both clients
retain all 21 paths after every commit and at later draws. Xray chooses the
retained root after commit twice, with the full cache present. These observations
confirm retention in this diagnostic; they do not explain individual choices in
the earlier ordinary checkpoint, estimate selection frequencies or close G2.
No production runtime, random choice or acceptance threshold is changed.

A separate frozen host calibration compares ordinary Xray with identical Xray
bytes/configuration: twelve three-round closeafter blocks, 360 captures. The
unchanged selected-path rate criterion rejects five blocks, including 10/15
versus 12/15 twice. CANCEL/timing checks pass throughout. Thus this rate failure
alone does not establish a C-specific defect. It neither reclassifies the earlier
native checkpoint nor estimates a population rejection rate; G2 remains open
under the unchanged policy. See docs/TESTING.md for every block and provenance.

The retained v1 ordinary host checkpoint runs live journals on container-local
storage, then exports them after cleanup. It uses the same executable bytes as
the preceding Windows-bind-mounted checkpoint: three paired rounds across
bigbody, gzbody, latebig and closeafter, 15 connections per client/scenario.
C/Go first-HEADERS medians are 347/472, 429/424, 421/488 and 357/533 us.
The absolute 100-us limit still fails for bigbody and closeafter; C is earlier
in those cases. Bigbody CANCEL is 7/15 versus 5/15 (13.3 points), above the
unchanged 10-point limit. Closeafter harvesting matches at 11/15. G2 remains
open. The preceding 463--613-us apparent C delay included synchronous logging
to a Windows bind mount; it is not intrinsic scheduling cost. Profile ownership
and cancellation interleavings without changing scheduling to fit stand timing.
These are host checkpoints, not new native acceptance or replacements for the
separate frozen 136-block experiment. See docs/TESTING.md for provenance.

The retained v1 ordinary native checkpoint on the test 4A covers all four scenarios
in three paired rounds (120 connections), with per-scenario first-role order
verified before launch and during analysis. CANCEL matches in each scenario
(bigbody/latebig 15/15, gzbody/closeafter 0/15); closeafter harvesting matches
at 11/15. Refund-before-redirected-HEADERS remains C 15/15 versus Go 0/15 in
bigbody. C's first-HEADERS medians are earlier by 3376--3668 us, outside the
unchanged absolute 100-us limit. G2 remains open. The preceding separate
60-connection fixed-order diagnostic observed both refund/HEADERS orders in
both clients; samples are not pooled or used to infer causality. Native cleanup
boundary fixtures pass. No scheduler winner or timing delay is forced. Exact
hashes, memory/restore checks and limitations are in docs/TESTING.md.

Fresh in-memory handoff tracing on the same candidate adds Do notify/wait/step
and request-queue milestones. In all ten traced C connections, first DATA is
handled after reset completion but before stream removal/donec. Do wait returns
after donec in four connections; six continue without another observed wait
return. Queueing follows donec in all ten. The early-DATA window therefore
precedes the Do handoff, narrowing inspection to Write completion and resumption
of the independent request/cleanup task. It is not evidence for changing Do
notifications or forcing cleanup onto the TLS owner. The active reference is
Go 1.27 net/http/internal/http2, not the build-tag-excluded legacy x/net file.
The separate 20-connection traced diagnostic does not measure G2 frequencies
or performance; source identity and restoration checks pass.

Split-mode input dispatch returns at a completed frame boundary when queued
output needs the sole TLS owner. `read_pending` records runnable buffered input,
separately from a real writer/Flush dependency; bufio and at most one accepted
feed tail remain owned until `read_step` resumes them. Another feed cannot
overwrite that tail. An already in-flight foreign Write does not block input.
There is no wait for request cleanup or scheduler sleep. Controlled real-worker
fixtures cover 32/5000 bytes, exact-once credit, stop, failure and deferred EOF;
they also pass natively on 4A. The matched 160-connection diagnostic still has
bigbody refund-before-HEADERS in C 40/40 versus Go 0/40. Ownership is tested;
G2 scheduling equivalence is not established. See `docs/TESTING.md` for evidence.

Reset completion does not execute its request continuation on the TLS owner's
stack. The separate executor resumes pipe closure / stream removal, then takes
the final writer-error check. ReadLoop may dispatch DATA while reset is in flight,
after its completion before removal, or between removal and that final check.
The 32/5000-byte fixtures exercise all three without making cleanup a read
barrier, and reject mutations adding that barrier or moving cleanup into the
TLS completion callback. Native 4A and sanitizer checks pass. This confirms
ownership under selected interleavings; it does not prove the relative frequency
of those interleavings matches Go's runtime.

Request-task progress and Write completion do not wake Do while Body.Close is
waiting solely for donec (O8). In that state a successful reset Flush and stream
removal change request-executor readiness, not Do's readiness. They neither
advance Do's generation nor broadcast its condition. Actual donec completion
publishes the generation and wake; stop, connection failure and OOM still wake
both tasks. A pending Close-credit continuation is excluded from this suppression.
No protocol continuation moves onto the TLS owner's stack and DATA is not held
until cleanup. The deterministic reset/removal/donec sequence now publishes one
Do notification instead of three; this is a notification count, not a measured
G2 distribution or throughput improvement. See `docs/TESTING.md`.
The subsequent matched native 160-connection diagnostic retains bigbody
credit-before-HEADERS in C 40/40 versus Go 1/40. The notification optimization
therefore does not close G2. Earlier traced DATA/cleanup positions describe
earlier candidates, not the current binary; current causality needs fresh
instrumentation. Device restoration and evidence checks pass.
That fresh trace now observes C DATA before redirected HEADERS in 10/10 bigbody
connections (9 between reset-send/completion, 1 before cleanup entry), versus
Go 1/10 (the other 9 follow removal and redirected HEADERS). The analyzer
separates removal from the local HEADERS marker. Reset-send precedes actual
socket Write dispatch, so this does not prove socket backpressure; the next
causal observation must distinguish queued reset work from TLS-owner dispatch.
This instrumented 40-connection sample is not performance or G2 acceptance.

The subsequent TLS-owner dispatch trace distinguishes queueing from socket I/O:
all 10 C bigbody DATA dispatches precede reset take, after reset-send; the later
conn_write calls all succeed without EAGAIN. The owner can observe an empty
queue before a producer publishes a Write, then enter feed/read_step. cc_run
now rechecks runnable output under the protocol mutex before parsing any frame,
including a fresh feed's first frame, rather than only after a completed frame.
Accepted input remains owned and yields to already runnable I/O. An in-flight
Write still permits reads; no producer wait, timer or cleanup execution is added.
The old source fails the new retained-input race regression. A second regression
covers fresh input. Native 4A, sanitizer, encrypted socketpair and full cross-target
gates pass; three mutations reject removing the check, skipping the first frame,
or blocking reads behind an in-flight Write.

The fixed-candidate follow-up trace has DATA after reset completion in all 10
bigbody connections, with successful socket results. Nine precede stream removal
and one follows removal; all still precede redirected HEADERS. Go's 10 DATA
dispatches follow removal and redirected HEADERS. Thus the demonstrated queued-I/O
window is fixed, while the post-completion cleanup/readLoop ordering still differs.
These bounded instrumented runs do not close G2 or measure a speed improvement.

The concurrent spider is separate from the historical uplink-reader proposal below and
from the record-opening pools used by established tunnels. One Do pthread and one
request/cleanup pthread are started for each `ST_SPIDER` session, inside its already-forked
worker process. Either creation failure rolls back startup and ends the session;
there is no synchronous fallback or scheduling delay.
The loop prepares completion/task ownership and submits the initial HTTP/2 Write
before creating either pthread. This follows `newClientConn`'s opening Flush before
its readLoop launch (`vendor/x-net/http2/transport.go:542-555`). If the socket is
backpressured, the retained opening still blocks readLoop and initial RoundTrip
until actual Write completion. An immediate opening error creates no workers.
Do is created before the request executor (O6), so initial request publication
can overlap the second native creation. This follows the reference's already
running Do/RoundTrip launching `cs.doRequest` in `internalRoundTrip`
(`vendor/x-net/http2/transport.go:948-966`). The request wait checks shared
readiness before sleeping: publication before executor creation cannot lose
the request. A deterministic fixture holds the second creation until Do has
published work, then verifies admission without another wake. Failure of the
second creation stops and joins Do before releasing the session.
Failures identify the startup stage and connection fd; pthread failures report
their returned error code, rather than an unrelated `errno`.
This is an implementation checkpoint, not a claim that G2 is closed.

The readLoop releases the shared state mutex between completed HTTP/2 frames,
including frames coalesced in one TLS record. This follows the pinned
`clientConnReadLoop.processHeaders/processData` lock scopes rather than treating
the record as an atomic batch relative to Do/Body.Close. Notifications are
published at that boundary; readLoop ownership and stop/closure are checked on
resumption. There is no enforced scheduler handoff or artificial delay. A real
Do pthread regression, isolated old-lock mutation, sanitizer run and native 4A
fixture verify the boundary and late-DATA refund ownership. A subsequent matched
160-connection diagnostic on 4A still observes bigbody refund-before-redirected-
HEADERS in 39/40 C versus 1/40 Go connections. CPU and HWM observations favor C
in this bounded workload, but do not establish an improvement over the prior C
build. Device, restoration and monitor all exit 0, with unchanged boot/configuration;
G2 stays open. See the dated checkpoints in [docs/TESTING.md](docs/TESTING.md).

A bounded instrumented follow-up attributes the refund paths on the same 4A.
At the initial redirect Close, C observes zero unread pipe bytes in all ten
bigbody connections, then accounts their credit when DATA meets a still-found
stream's broken pipe. Go accounts nine through late DATA without an active
stream and one through Close with unread data. The wire credit multisets match
the complete buffered traces. This narrows the next investigation to cleanup
and stream visibility relative to reset Flush; tracing itself changes execution
and does not prove the cause of the uninstrumented distribution or close G2.
Production and pinned vendor sources are unchanged by these diagnostic builds.

The following cleanup trace places C's first bigbody DATA handling inside the
pending reset Write in ten cases, and Go's after stream removal in ten. It does
not observe the hypothesized completed-Flush/pre-forget window. The TLS owner
now services its queued Writes before retained input, but still permits readLoop
progress under foreign socket backpressure. Terminal reads preserve already
queued plaintext/whole-Write completion; no producer continuation is run inline.
Focused/native fixtures and the full gate pass. The final uninstrumented
40-connection checkpoint still shows credit-before-redirected-HEADERS at 10/10 C
versus 1/10 Go, so G2 remains open. Further diagnosis concerns the duration of a
single accepted feed, rather than adding a scheduler delay. Details and hashes
are in [docs/TESTING.md](docs/TESTING.md).

A native MIPS wire checkpoint on 28 October executes this client on the test
4A: three rounds, 60 connections across bigbody, gzbody, latebig and closeafter.
Frame structure, redirect paths, latebig cancellation and retained harvested
paths pass. The full MIPS Xray staging attempt hits the memory safety guard;
the subsequent reference runs on the host. These are different hardware/path
conditions, not a paired scheduler or performance comparison. The differing
bigbody CANCEL counts therefore leave G2 open. Exact hashes, failed attempts,
resource observations and restoration checks are in [docs/TESTING.md](docs/TESTING.md).

The subsequent paired MIPS follow-up uses both C and a selected-module pinned
Xray distribution on the same 4A, with unchanged reference protocol sources.
Across 120 connections, both pass the four scenario invariants; bigbody CANCEL
is 15/15 for C and 14/15 for the native reference. This supplies a matched-device
wire checkpoint, not the missing worker/CPU budget or long-workload acceptance.
G2 remains open. The reusable reference adapter is
[`tools/vendorcap/nativeclient`](tools/vendorcap/nativeclient/README.md); exact
hashes, resource observations and the final-build native smoke are recorded in
[docs/TESTING.md](docs/TESTING.md).

The optional `bench-spider-workers` now observes blocked-opening creation and
stop on the actual 4A. Eight rounds of 1/2/4/8 sessions return task and wake-fd
counts to baseline each time. At eight sessions the observed median start/close
CPU is 6.9/4.0 ms and live RSS reaches 1528 KiB, returning to 1196 KiB after close.
This microbenchmark excludes TLS/network/body work and normal completed-task
retirement; its short-phase CPU counters and allocator plateau do not establish
production resource limits or G2 acceptance. The method, phase-boundary limits,
sanitizer/mutation checks and native hashes are in docs/TESTING.md.

The completed-HTTP resource mode now executes the normal retirement path on
the 4A: 120 sessions retire 240 HTTP workers while retaining TLS/readLoop state.
Their controlled encrypted peers authenticate 120 PING ACKs and 120 exact
late-DATA refunds after retirement; no HTTP threads restart. Eight-session task
counts fall from 17 to 1 before those probes, and final session/fd counts return
to baseline. This uses application-record socket pairs, not TLS negotiation or
a live node. CPU includes controlled-peer work, with coarse short-phase counter
behavior; the bounded memory plateau and full fixture checks do not close the
remaining G2 traffic/performance acceptance. Details are in docs/TESTING.md.

An additional native authenticated REALITY checkpoint verifies 455 responses
(650575872 bytes) over a five-minute load loop, with four concurrent streams and
a separate 20 MiB response. A two-process follow-up verifies 85 responses
(132644864 bytes), confirms traffic in both workers and preserves their PIDs
through supervisor diagnostic signals and a disposable-server restart. Both
clients recover without restart. Maximum sampled RSS is 2976 KiB for one process
and 6436 KiB summed across the supervisor and two workers; the latter includes
shared pages. This is a bounded download/reconnect test with a local pinned
Xray server, not a native-reference speed comparison, Hysteria acceptance or
spider execution. It leaves G2 open; exact methodology, failed controller attempt,
archive identities and verifier mutations are in docs/TESTING.md.

A later authenticated Hysteria test exposes a buffered-FIN truncation on 4A:
finishing a previous LAN Write was not counted as progress, and FIN could close
the session while QUIC still held an unread response tail. The copy loop now
continues after that Write and requires both buffers drained before closure.
The actual-driver socketpair regression, isolated old-progress mutation, native
MIPS execution, focused ASan/UBSan and full offline gate pass. A three-minute
mixed hardware workload verifies 370 TCP transfers (244973568 bytes), including
20 MiB in each direction, and 5700 UDP echoes; server-loss recovery preserves the
client PID. This is a copy/close correction, not a scheduler optimisation or G2
acceptance. Native UDP ceilings are also checked against the pinned Go client;
exact boundaries, failed attempts and resource observations are in docs/TESTING.md.

The preceding combined-readiness checkpoint passes native cleanup/socketpair/parallel-record suites on
the test MT7621 with matching executed hashes. The four-session worker fixture
reports RSS 1756 KiB versus 1608 KiB baseline, returning to baseline after all
workers join; startup/lifecycle CPU samples are 5291/7684 microseconds. These
bounded fixture costs do not establish production traffic performance. A fresh
matched 80-connection host diagnosis still observes current C/reference CANCEL
at 14/20 versus 4/20; the preceding write-first build gives 15/20 versus its
reference control's 10/20. Neither improvement nor G2 acceptance follows from
those small dependent groups. See docs/TESTING.md for identities and limits.

The opening-before-workers checkpoint has a separate fixed 80-connection host
diagnosis with identical current GHASH and other C modules in both builds. C first
destination-read medians are 222.5 us before and 68 us after; first-request medians
are 603.5 and 555.5 us. Their reference controls also move (first requests 316 and
283.5 us). All four C/reference groups have 10 CANCELs in 20 related retry
connections. This narrows the startup latency without proving G2 acceptance or
production-router performance. The executed wire snapshot precedes startup error
log additions, which are verified separately by the failure fixtures.

| Participant | Owns or drives | Must not do |
|---|---|---|
| Event loop | Session lifetime, socket I/O, TLS keys and record state, KeyUpdate, ciphertext queue, completion acknowledgments and `read_step` for retained readLoop input | Run Do/request task drivers or free fetch while either worker can access it |
| Do consumer | `lc_spider_fetch_wait/step`, body reads, gzip, redirects and harvest | Access socket/TLS state or event-loop scratch buffers |
| Request task | `lc_spider_fetch_request_wait/step`, owned request fields, HPACK encoding, Write continuations and cleanup | Take Do's private-work lock, run body/redirect work, or access sockets/TLS |
| Shared fetch | HTTP/2 state, saved continuations, input and whole-write queues, protected by its protocol mutex | Treat the mutex as lifetime protection or hold it across socket waits or private redirect preparation |

The consumer takes `do_lock` before the protocol mutex in step/settle. Feed, completion and
stop take only the protocol mutex, as does split mode's `read_step`. Preparing a redirect's URL and header map releases the
protocol mutex while retaining `do_lock`; these fields are private to Do. Published response
metadata remains stream-owned until stop/join/free. After reacquiring the protocol mutex,
Do restores its execution context and checks stop/connection failure before advancing.

Gzip construction and inflation likewise hold only `do_lock`. Their source
callback acquires the protocol mutex for pipe consumption, flow accounting and
matching Write ownership, then returns owned bytes valid until the next source
Read. Concurrent feed may compact or grow the pipe without changing that result.
Stop/connection failure is checked before a new source Read and after private
inflation returns. Request cleanup, readLoop and PING acknowledgments do not
wait on decoder work. The shared fixed-Huffman table uses process-wide
`pthread_once`, matching Go's `fixedOnce.Do`; separate fetch mutexes cannot
protect initialization shared by every decoder.

### Writes and backpressure

The last queued Write transfers its allocation to the TLS owner (O7), instead
of allocating and copying the same payload again. A prefix followed by other
Writes is still copied, leaving their storage and boundaries intact. Detached
storage cannot be reused by a producer, even while its Write is backpressured.
The caller frees it after use; fetch destruction must not free it. This changes
allocation ownership only: take is not completion, and failure still releases
the matching writer and closes the connection. No buffer pool is retained.

Both workers coalesce eventfd notifications across immediately runnable steps
(O5). The last result is release-published before the one notification at a
quiescent, own-Write wait or terminal boundary. Neither worker waits for the event
loop to advance a private continuation; actual Write completion still comes only
from the TLS/socket owner. There is no timer, arbitrary batch size or extra Do
driver. A task's normal terminal return publishes a separate completion wake so
its native thread can be joined even if the earlier quiescent wake was consumed.
This is a lifecycle notification, not another protocol continuation or Write.

The shared task result itself is now published only after the runnable batch,
instead of storing rc=1 after every internal phase. The TLS owner tests these
fields only for terminal errors; it does not use rc=1 to drive a task. Result
release-publication still precedes the done flag and eventfd notification.
The four-phase fixture checks hidden intermediate results and observes the final
result at the actual eventfd write, for both tasks and every supported terminal
outcome. The old source and isolated intermediate/late-publication mutations fail.
This reduces status publications, without merging cleanup phases, removing a
protocol-lock boundary or changing task readiness. Native 4A and sanitizer
evidence is in docs/TESTING.md; no network speed or G2 acceptance is inferred.

Do and request/cleanup have separate condition variables (O8). A publication
wakes the request executor only if its existing readiness or completion predicate
is true; unrelated input leaves that task asleep. A quiescent Do step notifies only
ready request work, without advancing Do's own input generation. Stop, OOM
and connection failure wake both channels. The blocked-wait tests synchronize
on actual entry into cond_wait, then publish work, stop or loss; no scheduling
sleep or timer selects the result. Initialization failure destroys only the
condition variables already initialized. These are notification changes,
not new cancellation decisions or altered Write completion boundaries.

Successful request-task stream admission does not advance Do's input generation
or broadcast to its condition variable. The pinned `ClientConn.addStreamLocked`
assigns the stream under cc.mu without publishing a response, abort or donec
event. The request task remains immediately runnable for its independent writer
turn. Encoding, rejected admission, cleanup and terminal errors retain their
notifications; stop produces no extra task progress. This removes one needless
Do publication per successful admission, without merging either task or adding
a scheduling delay. Six deterministic outcomes and three isolated mutations
cover that boundary; fresh wire observations belong in docs/TESTING.md.

Socket readiness bits are independent. `spider_socket_event` preserves READ when
the same event also reports WRITE, including after a blocked Flush completes.
The socket/TLS owner remains the event loop; neither worker performs I/O.
The read pump still waits for its own ClientConn writer and KeyUpdate reply.
This does not force Body.Close to wait for new input or suppress a selected CANCEL.

`take` transfers independently owned bytes for one whole logical Write. It does not
complete that Write. The loop retains the bytes and plaintext offset across partial
socket writes and EAGAIN, sealing another TLS record only after pending ciphertext has
reached the socket. `write_complete` is called after the entire logical Write completes,
or with failure; completion identities release the matching producer's continuation.
The transferred allocation remains the loop's responsibility to free.

Request header production retains the encoded HPACK block, stream and offset between
steps. HEADERS/CONTINUATION ordering and the writer's ownership must survive a pause;
protocol ACKs cannot be inserted into an unfinished header block. Body reads that wait
for their own flow-credit Write retain accounted bytes in a separate allocation rather
than keeping a pointer into a pipe that another operation may compact or reallocate.
Saved cleanup state prevents duplicate cancellation on resumption.
SETTINGS acquires its ClientConn's writer even for ACK, as pinned x/net's
`processSettings` does; PING ACK does not. Frame parsing and CONTINUATION-order
validation precede that acquisition, while setting validity is checked afterward.
A waiting control frame retains its payload and bufio tail. Another ClientConn's
unfinished socket Write neither blocks its writer acquisition nor completes it.
Writing cleanup publishes its pipe error only after the reset's successful matching Flush
completion. That completion wakes a Read which drained the pipe while the reset owned cc.wmu;
stream removal follows. The final cc.wmu/werr acquisition and donec are a separate phase even
when the writer was free at removal. Sticky werr belongs to the ClientConn that produced the
failed Write; its matching ownership is released on failure. An already-forgotten stream can
finish this terminal check after connection failure without advancing Do or producing bytes.
donec means cleanup completed, not that a Write succeeded. Stop takes precedence over that
terminal phase. Cleanup that had not reached removal is not newly driven by the terminal pass.

DATA publishes its body and accounts flow before waiting for cc.wmu. Its saved continuation
waits first for the writer and then for the padding WINDOW_UPDATE Flush; reset and END_STREAM
follow that completion. DATA for forgotten streams uses the same writer phase for connection
credit. A non-writing cleanup can remove a stream behind another Write, including a request
Write belonging to another stream; wait/step readiness admits that phase while donec still
waits for cc.wmu. It cannot enter cleanup while its own request_writer is active:
doRequest calls cleanup only after writeRequest returns, even when peer abort has already
woken RoundTrip. Own-request stop/error and successful no-new-input completion are tested.

Body.Close also has a pre-writer phase: break/drop the pipe, abort the stream and account unread
connection bytes once, before cc.wmu is available. Its saved credit phase acquires the writer
even below the WINDOW_UPDATE threshold. `close_writer` and the matching Write id protect its
Flush against protocol ACKs and cleanup's final writer check. Do waits for both that Flush and
cleanup's donec before following the redirect. A received response can be handled behind an
unfinished request Write; this does not release the request owner or authorize a conflicting Write.
In the completion driver, Close signals the abort but does not execute doRequest cleanup inline.
The request task decides whether to reset; END_STREAM arriving between the two phases can suppress
CANCEL. END_STREAM after a reset was selected cannot retract that Write. This is a semantic
handoff, not a timed scheduling delay.

Backpressure is tied to protocol operations and their Write owners, not an artificial
byte cap or a sleep. Independent pipe reads and flow accounting can run behind readLoop,
request and cleanup Writes. A Read that needs credit waits for the writer and its own Flush;
only matching completion allows its saved bytes to return. Reads without credit, including
gzip output already buffered by its reader, can advance to EOF/error behind those owners.
That does not authorize another request or a conflicting writer. Cleanup acquisition now uses
its own ClientConn's writer predicate, not global output emptiness: cc.wmu/bufio/Framer are
per ClientConn, while queue cuts serialize the shared TLS socket. A queued reset retains its
own owner and matching completion id behind a foreign ClientConn's unfinished Write. Neither
local completion nor final cleanup may acknowledge that foreign id. The request task also
acquires only its own ClientConn writer: another ClientConn's unfinished socket Write
does not postpone encoding or cancellation before encoding. Its own opening, ACK and
request Flush remain barriers. A newly queued HEADERS Write keeps its own completion id
behind the foreign Write; socket ownership and ordering are unchanged.
Read and Close credit also acquire only their own ClientConn's writer, following
`transportResponseBody.Read`/`Close` in the pinned `http2/transport.go:2173-2263`.
A Read retains its accounted bytes while waiting for that writer, then for its own
Flush id. Readiness follows those local dependencies, including a writer release
while foreign output is still queued. A foreign completion cannot return the Read's
bytes or finish Close. A free socket queue does not authorize taking an owned writer.
Initial RoundTrip admission waits for its opening Flush, not a later readLoop ACK.
The pinned `internalRoundTrip` starts `doRequest` at `transport.go:966`; stream
allocation at :1120 precedes `encodeAndWriteHeaders`' writer acquisition at :1221.
Do queues owned fields and a connection reservation with stream ID zero.
The request task then checks connection usability and peer concurrency under
the protocol mutex, consumes the reservation and assigns the next odd ID.
This follows `writeRequest`/`addStreamLocked`; a later separate continuation
acquires cc.wmu for encoding. Admission waits for its own opening Flush, but
does not wait for a readLoop ACK's writer. The worker immediately drains both
runnable continuations, without another event-loop round or scheduling delay.
Before admission, stream lookup cannot find that request: unsolicited DATA
therefore fails the connection, while reset for the unassigned ID is ignored.
Stop before execution cannot consume an ID; a changed peer concurrency limit
is checked before assigning one. Eight public-driver cases additionally exercise
SETTINGS/PING, stop, Write failure and abort before encoding. Two additional
TLS/socket-EAGAIN cases verify ACK then HEADERS at the peer.
After the previous Body.Close and cleanup finish, redirect continuation likewise admits
the next RoundTrip without waiting for a readLoop ACK or another ClientConn's Flush.
This follows Go 1.27 `Client.do`, `src/net/http/client.go:726-746`. Owned request fields
are queued without HPACK mutation; only the request task subsequently acquires cc.wmu.
Eight public-driver scenarios cover own/foreign ACK ownership, stop and failure before
admission, stop after admission and exact completion order. Two additional TLS/socket
cases cover redirected stream 3 behind an actual SETTINGS/PING ACK at EAGAIN.
Backoff/retry and other producer resumptions still use conservative queue gating; their general
interleavings remain under development and have not been relaxed without a boundary proof.
Whole-write preservation and passing tests do not by themselves prove equivalence to Go's
independently scheduled goroutines.

### Input, wakeups and shutdown

The TLS owner consults `lc_spider_fetch_read_ready` before opening another record.
Before opening Flush completion, neither take nor accepted early input starts readLoop:
one accepted feed may be held and resumes after the matching opening completion only.
Fetch may retain a complete blocked frame and the tail of one accepted feed; it must
not accumulate an unrestricted queue of later decrypted records. KeyUpdate replies
stay loop-owned, ordered with application Writes, and preserve the TLS read boundary
until the required reply Write completes.

In split mode only the loop drives retained readLoop input. `spider_drain` calls
`lc_spider_fetch_read_step` even when a later logical Write/ciphertext remains pending,
and before each new take. Accepted frames and the held tail advance behind another
task's Write. The reader waits at a complete PING/SETTINGS frame needing its own
ClientConn writer, DATA credit needing that writer, or its own outstanding Flush.
A frame already dispatched cannot retain writer ownership through its stale header.
The opening still precedes the readLoop. The driver also runs on worker progress
before another socket wait.
The callback takes only the protocol lock, not Do's private
lock. It resumes complete frames/held input, not Do/body or request cleanup. No work
is done inline in Write completion. Whole-Write ids and the other producer gates
remain unchanged; an unfinished readLoop ACK still blocks its next frame.
Do's step no longer resumes those readers in split mode. Legacy combined mode is
unchanged and rejects the separate readLoop driver. Pending EOF cannot overtake
accepted reader continuations: Do defers the loss until their frames/tail are processed,
then retains its existing body/harvest/cleanup-before-loss behavior. Quiescent reader
calls do not manufacture generations, output or completion.

The Do worker waits on a generation/predicate condition under the fetch mutex. Real retry
deadlines use `CLOCK_MONOTONIC` there; the event loop must not poll a stale copy of an
expired retry deadline. An eventfd notifies the loop of worker progress. It is a wakeup,
not completion, and must not be used to infer that a particular input was processed.

Socket EOF/error is handed to the Do consumer so already-fed response bytes and saved
body continuations are not discarded before their final turn. Ending Do alone does not
close the HTTP/2 connection: its readLoop can still service control frames.

Session teardown is **stop -> join both tasks -> release fetch/TLS/session resources**. Stop wakes
both task waits, including completion waits. Join must not hold a lock either task needs.
The wake descriptor stays alive until both tasks have joined. Session memory remains
subject to the event loop's deferred reaping, since other events in the same epoll batch
may still reference it. A failed partial startup follows the same resource cleanup path.

### Queued request versus writer acquisition, 7 October 2026 (current checkpoint)

Do's request submission previously reserved `request_writer` before the separately
scheduled request task entered encodeAndWriteHeaders. A valid readLoop PING or
SETTINGS could not acquire the writer during that interval. The exact preceding
production checkpoint reproduces the missing actual ACK through the public driver:
`artifacts/lite-client/diagnostics/request-acquisition-20261007`.
Pinned Go 1.27 acquires cc.wmu on encodeAndWriteHeaders entry, not Do submission.

`request_pending` now owns queued fields and the existing header-producer
reservation without claiming cc.wmu. The request task moves it to `request_writer`
only when the actual writer is free, then checks abort before encoding. An active
request still owns its complete HEADERS/CONTINUATION/Flush sequence. Own cleanup
excludes both queued and active request phases; otherwise peer abort could unwind
writeRequest before it returns. Stream allocation has since moved from Do to
the request task, as specified by the current admission contract above. Other
global output gates remain conservative. This is not a complete scheduler port.

Ten new public-driver cases cover PING/SETTINGS, success, stop, ACK error and abort
on either side of the ACK. They require unchanged HPACK before writer entry, real
SETTINGS accounting, quiescent generations, no premature cleanup or duplicate Write,
and completion without fresh input. Two additional tunnel cases explicitly schedule
the public task turns, then decrypt exact ACK-before-HEADERS through real TLS/socket
EAGAIN; they do not claim worker-thread scheduling equivalence. The fixture uses
actual session_close/reap. The first gate's fixture direct-free error is preserved,
not a pass: `checks/20261007-103114/failure-reviewed.txt`.

Final gate `artifacts/lite-client/checks/20261007-103339` passes focused tests,
fully instrumented fetch/cleanup ASan/UBSan, the full offline gate (8234 `ok` lines,
not independent tests), both architecture/plane builds and 45 QEMU crypto checks.
All 316 source/test/Makefile manifest entries match the working tree. Two controls
pass and three private mutants are rejected at intended driver/socket assertions:
`diagnostics/request-acquisition-mutations-20261007-v2`. The candidate binary is
924f9f70f7839dbac85dcd760a3c3393fb833e35fb947b7835a66c6cd466e3d5.

The separate fixed 60-connection diagnostic has its own frozen plan and evidence
under `diagnostics/request-acquisition-wire-20261007`; it is not acceptance and
does not isolate the two changes since the preceding wire checkpoint. It completes
with all guards and independent counts passing: current C/reference CANCEL 15/20
versus 6/20; separate original-control rounds 8/10 versus 4/10. The +45-point
descriptive candidate gap remains observable. Small unequal retry groups do not
establish improvement, regression, equivalence or causality. Original
full-run evidence and the normal measurement checkpoint are unchanged. No current
TSan/native acceptance, long run, router access or G2 closure is claimed.

### DATA terminal phase after padding Flush, 7 October 2026 (preceding checkpoint)

The preceding readLoop checkpoint retained another unnecessary dependency:
`read_step` postponed DATA's saved END_STREAM after its own padding Flush if a
later body Read/Close owned the writer. A deterministic public-driver reproduction
is retained in `artifacts/lite-client/diagnostics/data-terminal-boundary-20261007-v3`.
The pinned actual Go 1.27 processData unlocks cc.wmu after Flush and performs its
terminal actions without reacquiring it. This is a padded-DATA boundary proof,
not evidence of the cause of the measured unpadded bigbody cancellation gap.

The loop now executes only that completed DATA terminal phase behind pending
output, preserving the later Write id and the unparsed buffer/tail. It does not
relax other producer gates or parse the next frame. Stop/error still prevents
terminal publication. `spider_drain` consults the real API while ciphertext remains
backpressured; the tunnel fixture counts calls without substituting API behavior.
Twenty further driver scenarios cover Read/Close owners, buffered PING/no tail,
stop/error at the own-padding and later-body boundaries, exact credit, no duplicate
wakes and cleanup selecting no CANCEL after the already-accepted END_STREAM.

Gate `artifacts/lite-client/checks/20261007-101433` passes focused tests,
fully instrumented fetch/cleanup ASan/UBSan and full offline verification (7998
`ok` lines, not independent tests), both architecture/plane builds and 45 QEMU
crypto checks. Two mutation controls pass and both targeted mutants fail their
intended assertions in `data-terminal-mutations-20261007-v2`. Earlier fixture and
incomplete-link-harness attempts are preserved, not passing verification.
All 316 compiled-source entries and 1022 original evidence hashes remain unchanged
after checking. The preceding 16/20 versus 10/20 short-wire totals below are not
results for this new source. No current TSan pass, wire/native acceptance, long run,
checkpoint replacement, router access or G2 closure is claimed.

### Independent readLoop continuation, 7 October 2026 (preceding checkpoint)

The earlier deterministic private-Do counterexample below is now addressed by
the loop-owned `read_step` contract above. Thirteen further public-driver scenarios
keep real redirect preparation paused and exercise buffered/held input, both actual
Write boundaries, stop/error, invalid DATA and EOF before saved input. They require
exactly one ACK/body/credit/END_STREAM and no quiescent generation changes. Two real
TLS backpressure cases require resumption directly from `spider_drain`, before a Do
wake. No third thread, scheduling delay or incidental producer-gate relaxation is added.

Final gate `artifacts/lite-client/checks/20261007-091950` passes focused
fetch/cleanup/tunnel, fully instrumented fetch/cleanup ASan/UBSan and full offline
verification: 7489 `ok` lines, both architecture/plane builds and 45 QEMU crypto checks.
All 316 source-manifest entries match the working tree. Uninstrumented host candidate:
`d8c7b04faa7c433255f5e33f93ad78076b4298771e221f5e74afe6856b9b8f0c`.
Two controls pass and three private mutants are caught at their intended assertions
in `artifacts/lite-client/diagnostics/readloop-mutations-20261007-v7`: private Do lock,
early transport loss, and skipped loop-owner resume with buffered TLS input.
Earlier corrected-fixture/harness attempts remain separate, not passing gates.

The 64-session x86 fixture reports 8332 KiB RSS (2772 KiB baseline), startup CPU
16335 us and lifecycle CPU 22585 us. Two 8 MiB virtual stack reservations remain;
these are not resident stack sizes or native router budgets. No current TSan pass,
wire acceptance or resource acceptance is claimed. Original 136-block evidence
(1022 hashes) and the saved measurement checkpoint remain unchanged. G2 stays open.

The new uninstrumented candidate's separate fixed four-round wire diagnostic,
`artifacts/lite-client/diagnostics/readloop-wire-20261007`, completes 60 connections
with all frozen stand/input/executed-identity guards passing. Frozen-parser totals
agree with independent raw-frame counts: C/reference CANCEL 16/20 versus 10/20;
original-control C/reference in separate rounds 8/10 versus 3/10. The descriptive
candidate gap is +30 points, not an acceptance result. Unequal small retry groups
and role-order variation cannot establish improvement or cause. Boundary regressions
pass, but the wire gap remains observable; remaining producer/admission and writer/input
ordering needs evidence-based diagnosis. Original 136-block evidence is not pooled,
and no long run, checkpoint replacement or router work starts here.

### Separate request task, 7 October 2026 (preceding checkpoint)

The tunnel enables `lc_spider_fetch_request_tasks` before publication. Its Do worker
drives `step/wait`; a separate worker drives `request_step/request_wait`. Initial
HEADERS production, request continuation and cleanup run in the latter task, not
Do's immediate continuation loop. It takes only the protocol mutex, never `do_lock`,
so normal cleanup can finish while Do prepares a redirect outside that mutex.
Do copies request fields into stream-owned storage; encoding and sentHeaders publication
occur only on the request task's first writer turn, after checking abort. Dropping a
request before that turn must not change HPACK or send HEADERS/reset. Stream allocation
and header-producer reservation still occur on Do's turn; other producer gates remain
conservative. This is not a complete port of Go scheduling.

Reset/error/PING selection still precedes the writer wait. Actual Write completion
releases owner fields and wakes the request task; it does not run cleanup inline.
Forget and the final writer/werr acquisition remain separate phases. Request waits
use readiness predicates only, not Do's retry timer or arbitrary generation changes.
Quiescent Do steps must not manufacture their own input generations. Shared state is
serialized under the protocol mutex; neither task touches TLS or sockets.

The old combined driver is retained for synchronous callers/tests; its tests alone
cannot validate the tunnel's split mode. Ten new split-driver scenarios cover
cleanup while private Do is paused (five completion/stop/error cases), END_STREAM
before/after reset selection (two), quiescent generations and both stopped waits,
and invalid zero-frame SETTINGS/API misuse plus cancellation before HPACK encoding.
Tunnel tests also check rollback if
either thread creation fails, actual socket boundaries and joining both tasks.

The first seven-case source snapshot passed focused fetch/cleanup/tunnel tests and
ASan/UBSan in `artifacts/lite-client/checks/20261007-082239-a1dd0f3b`; later idle/invalid-input
cases and the final wait-error handling are not covered by that earlier result.
Its x86 fixture with 64 live stranger sessions observed 8148 KiB RSS (2668 KiB
baseline), 16000 us startup CPU and 21666 us total lifecycle CPU. Each task reserved
8 MiB of virtual pthread stack, two per stranger fetch; these are not resident
memory measurements or router resource budgets. No stack-size tuning or native
resource acceptance has been done. G2 and hardware acceptance remain open.

The preceding request-task source snapshot passes focused fetch/cleanup/tunnel tests, fully instrumented
fetch/cleanup ASan/UBSan and the full offline gate (7103 `ok` lines, not independent
tests), under `artifacts/lite-client/checks/20261007-083606`. Its uninstrumented
host binary is `01fe10e7ca9f99ebdc5423750eba5b48d09c68c762f404d2e142a8bc49b77642`.
The post-Do PING fixture now waits for both readLoop readiness and Do completion;
readLoop readiness alone does not imply Do has finished. The preceding failed and
superseded attempts are retained with explanations, not counted as final passes.
Two private mutants (encoding an already-aborted request, and inline cleanup from
Write completion) fail their intended assertions; the control passes. The final
64-session fixture reports 8228 KiB RSS against a 2720 KiB baseline, 15791 us startup
CPU and 21978 us total lifecycle CPU; both 8 MiB virtual stack reservations remain.
These are local fixture observations, not native budgets.

The supplemental TSan binaries build, but the first test stops before execution with
`ThreadSanitizer: unexpected memory mapping`, exit 66. Its receipt explicitly records
zero completed tests and no TSan pass; no retries or host ASLR changes were made.
This attempt provides no conclusion about races.

The fixed, uninstrumented four-round bigbody diagnostic at
`artifacts/lite-client/diagnostics/request-tasks-20261007` completes all 60 connections
and verifies executed identities and source/input guards. Candidate/reference CANCEL
is 14/20 versus 11/20; old binary/reference is 4/10 versus 1/10. These unequal, small
groups do not establish improvement, equivalence or causality. Candidate CANCEL remains
70% in both role orders, and both roles still emit resets before the 5000-byte refund
in some connections. The earlier full experiment is unchanged and is not pooled with
this diagnostic. G2 remains open; the measurement checkpoint and launchers still point
to the old binary, not this candidate. No full experiment or router work starts here.

The follow-up fixed trace, `artifacts/lite-client/diagnostics/split-trace-20261007`,
checks this same split source without changing production: 40 connections, ten complete
trace buffers, no dropped entries and matching wire/trace CANCEL counts. All ten buffers
show readLoop continuations inside Do steps (28 resumptions total). Six select CANCEL
before DATA; four process END_STREAM before the cleanup decision and do not reset. One
of those four closes with peer_closed still false, then the independent request task
decides after END_STREAM. These are observations, not a causal explanation of the gap.

A separate public-driver counterexample pauses real private redirect preparation,
feeds PING and END_STREAM behind the request Flush, then completes that actual Write.
The writer is free and the request task has no runnable work, but read_ready remains
false and the accepted frames are unprocessed until Do returns and steps. Source guards
pass. This exposed the dependency in that snapshot: `fetch_settle_locked` was the sole resumer
of writer_wait and held input, and is reached through the private Do lock. Go's readLoop
is independent. The counterexample is diagnostic evidence of a missing continuation,
not a regression test endorsing the observed dependency. Its source and log are retained
in the trace directory; production is not patched in this diagnostic checkpoint.

The correction specified at that checkpoint was to give the TLS/event-loop owner a protocol-only readLoop
continuation independent of Do, without running Do/cleanup from Write completion.
Preserve whole-Write ids, retained input bounds, control-frame writer exclusion, stop/error
and the pre-writer reset decision; do not relax global producer gates incidentally.
Public-driver regression tests must hold Do at that same private checkpoint and prove
continuation after success, stop/error behavior, no duplicate ACK/refund/END_STREAM and
no requirement for fresh input. Tunnel integration needs its own verification.

### Evidence and remaining limits

`test-fetch-cleanup` combines white-box state observations with the production public
feed/wait/step/take/write_complete driver. It checks non-writing cleanup behind foreign
readLoop Writes and forbids cleanup before its own request Write returns, including stop/error.
It covers forgotten-stream input, actual completion without fresh input,
and absence of duplicate output. DATA cases cover a busy/free writer, accounting before the
wait, END_STREAM after the padding Flush, stop/error at both boundaries and forgotten-stream
credit. Local predicate cases additionally cover body/cleanup owners and a stuck writer.
Close adds 22 public-driver cases: request/readLoop owners, 0/1/5000 unread bytes, stop/error
before writer acquisition and during Close's credit Flush, late PING input, and resumption
without fresh input or duplicate credit/reset. Removing Close's writer ownership makes the
late-PING test fail. Read adds 32 request/cleanup-owner cases, plain/gzip with/without credit,
stop/error before writer acquisition and during its own Flush, exact saved bytes/credit,
unchanged foreign Write identity, blocking readiness and no-new-input completion. Returning
a saved Read before its actual Flush completion makes these fail. Cleanup-owner Read cases also
require pipe error to be absent before reset Flush completion, and require that completion to
wake the drained reader without new input. The intermediate early-error assertion was corrected;
its older snapshot is retained separately, not used as terminal-boundary evidence. Eight additional
Close handoff cases cover unread credit, END_STREAM on either side, stop/error and no-new-input
completion. Three concurrent redirect cases pause private preparation and exercise feed/completion,
stop and write failure from another thread, verifying the protocol mutex is available while the
consumer guard remains held. A mutation retaining the protocol mutex fails this boundary assertion.
Ten late-DATA cases additionally cover Close before body input, completed CANCEL, the redirect's
new request Write in flight, and an old stream's connection-only credit behind that Write.
They exercise END_STREAM present/absent and stop/error before and during the credit Flush.
Repeated steps must preserve both streams and never repeat refund/reset. A mutation dropping
old-stream DATA only after stream 3 is allocated fails this new boundary assertion.
The own-request checkpoint has 116 public-driver cases and seven supplementary local checks. Its 28 new cases
cover a free/busy final cleanup acquisition (4), opening input/completion/stop/error (3),
actual DATA body consumption before Flush and broken-pipe refunds (7), plain/gzip actual
harvest-commit calls under EOF/error/stop (8), and two real ClientConns with non-writing/writing
cleanup behind a foreign socket Write (6). The earlier three own-request cleanup fixtures and
forgotten-DATA fixture are corrected without increasing the case count. Eight driver-targeted
mutants fail the assertions; the ninth fails the local sticky-werr assertion. The control passes. Both HYSTERIA planes,
fully instrumented fetch-driver ASan/UBSan and three TSan runs pass; the fresh full offline gate
prints 6613 ok lines and includes both architecture/plane builds and 45 QEMU crypto checks.
These establish the tested continuations, not fairness or scheduler equivalence.

The later pre-writer cleanup checkpoint adds five public-driver cases (121 plus seven local
checks). Go chooses its reset/error/PING before `writeStreamReset` waits for `cc.wmu`; the C
cleanup now retains that decision while the writer is busy. END_STREAM received during the
wait cannot retrospectively suppress an already selected CANCEL. The fixture holds an actual
Close WINDOW_UPDATE Write, attempts cleanup through `step`, feeds END_STREAM, and completes
the writer through `write_complete`. It checks no duplicate refund/reset, completion without
fresh input, stop, and errors of either Write. The prior source fails the exact reset assertion;
the corrected source passes focused fetch/tunnel tests and ASan/UBSan. A fresh isolated offline
gate passes with 6739 ok lines, both architectures/planes and 45 QEMU crypto checks. The three
TSan results above belong to the preceding checkpoint, not this newer source. This boundary
correction is not established as the cause of the observed excess bigbody CANCEL rate.

The preceding 88-case snapshot passed natively in the HYSTERIA=0 fixture on the non-production
MT7621 with 1180 KiB peak RSS and 154019 us CPU. Those native numbers do not apply to this new
snapshot and do not establish paired native wire acceptance. The 800-connection phase diagnosis,
resource recheck, new local gate and fixed next experiment are recorded separately in docs/TESTING.md.
Router wire acceptance/resource budget remain open and are outside the approved local-only plan.

`test-fetch` covers saved request/body continuations and write ownership;
`test-spider-tunnel` exercises the actual tunnel handoff with socket EAGAIN, KeyUpdate
ordering, worker-start failure and repeated/multi-session teardown. Sanitizer and gate
results, binary hashes and paired Xray measurements belong in [docs/TESTING.md](docs/TESTING.md).
A result applies to its tested snapshot, not later edits by another session.

G2 remains open in [DIVERGENCES.md](DIVERGENCES.md). Protocol fidelity is the requirement;
copying Go's internal scheduler is not. Changes must be judged by protocol invariants,
repeatable lifecycle tests and repeated wire measurements, not a tuned fixed delay.
Host pthread stack reservations and RSS samples do not establish a router resource
budget; device portability and concurrent-session cost need separate validation.

## Private executor-cache checkpoint — 2026-10-26

A private experiment reuses completed native workers, retaining at most two
idle threads without limiting active tasks. Its lifecycle fixture passes
sanitizers and native MIPS/AArch64 execution, but the full spider's paired wire
checkpoint still fails G2; the cache is not adopted. Standalone fixture results
are not hardware execution of the complete spider prototype.

Dispatch instrumentation shows no reuse in the initial bigbody burst: its ten
task starts all create threads. With closeafter, all ten starts reuse workers.
At that checkpoint Do/request wait loops retained executors while their TLS
connection remained alive, beyond the completion of an HTTP task. Pinned
Xray's get goroutine and x/net's doRequest have task lifetimes independent of
that retained connection/readLoop. Reclaiming an executor must therefore be
proved separately from stopping the fetch or closing transport; it must preserve
late input, request cleanup and Write completion. The experiment does not
establish the cause of the excess CANCEL rate. Exact controls, separate noisy
and quiet runs, limits and identities are recorded in docs/TESTING.md.

## HTTP executor retirement with retained readLoop — 2026-10-26

Pinned Xray `reality.go::UClient` explicitly retains the connection after its
get goroutine returns. In x/net `clientStream.doRequest`, request work ends
only after `cleanupWriteRequest` completes the final writer/error check and
closes donec. The split C driver now has these independent lifetime boundaries:

- Do's wait returns normally at DO_END, without stopping the fetch.
- The request executor finishes only after Do has returned and every producer,
  owned writer and stream cleanup has finished. Do completion wakes an already
  parked request waiter; completion cannot overtake an in-flight request Write.
- Each native thread release-publishes a completion flag, notifies eventfd and
  returns. The event loop joins completed workers and clears their live flags.
  It does not stop/free fetch, close TLS, cache threads or restart executors.
- The retained readLoop still acknowledges PING and refunds connection credit
  for late DATA on forgotten streams. After Do ends, readLoop also owns deferred
  EOF, after accepted frames and queued Writes actually complete. Active Do's
  existing body-before-EOF rule is unchanged.

Public-driver tests exercise a genuinely parked waiter, pending request Flush,
post-completion PING and deferred EOF. The tunnel fixture uses actual encrypted
socketpair input, EAGAIN, late 4096-byte DATA and combined READ/WRITE with EOF.
Six isolated mutations are rejected, and restored controls pass. The complete
offline gate, focused ASan/UBSan/TSan and both native MIPS/AArch64 suites pass.
Native fixtures preserve boot and AWG interface identity; no installed client
or service changes. Device test limits and paired wire evidence belong in
[docs/TESTING.md](docs/TESTING.md). This fixes executor lifetime, not G2 acceptance
or a demonstrated tunnel-throughput regression.

## Hysteria receive-pool notification refinement — 2026-10-26

The 2026-10-27 socket-wait correction is independent of notification tuning.
An unsuccessful connection poll now returns before draining the send queue's
wake pipe, preserving EINTR, the original terminal errno and the pending wake.
The writer propagates a non-EINTR poll failure without another sendmsg attempt.
Deterministic old-source failures, the offline gate, focused sanitizers and
native 4A/AX3000T fixtures validate these paths; packet timing and the sender's
150 us active-wait policy are unchanged. See docs/TESTING.md for scope and limits.

The O2 pool retains one opener per available extra CPU, capped at seven. A
batch with no datagrams publishes its job without notifying sleepers. A batch
smaller than the pool signals at most one worker per datagram; a full batch
still broadcasts. Workers check job under the protocol mutex before parking,
so a worker returning from the preceding batch cannot miss new work. Slot
claims and the release/acquire completion counter are unchanged; the owner
still completes unclaimed work and delivers results in input order. Stop
broadcasts to the complete pool before joining.

The fixture checks zero-to-32-datagram batches against serial opening for all
three ciphers and observes notification boundaries and full-pool shutdown.
Three broken notification policies are rejected. The full offline gate,
focused sanitizers and native 4A fixture/closed-port recovery pass. The matched
prototype timing differences are small and mixed, not a demonstrated speedup.
No worker count, sender spin interval, packet format or retry changes. The
preceding five-minute baseline soak and two later MIPS attempts are retained
resource-stop failures. A separate five-minute native AX3000T run passes all
277 checksum-verified responses. With the owner's approval to pause the test
4A's existing VPN/control services, an isolated five-minute MIPS run also passes
251 responses; four concurrent request generators then pass 400 responses
through one native process. This establishes the isolated native lifecycle,
not coexistence with the router's background control workload. Boot/configuration
are unchanged and the original services are restored after each run.
The fixture also rejects failure to unwind partially created pools and failure
to report construction errors, with native MIPS and focused sanitizer checks.
Exact identities, limits and evidence are recorded in docs/TESTING.md.

## Historical uplink and record-opening work

The sections below preserve the measurements and decisions made at their stated dates.
Their proposals and claims of "one difference left" are historical, not the current
spider architecture or a replacement for the divergence register.

⚠️ **Status, 2026-09-23: the table below is the baseline of 2026-09-19/20, not the state now.**
Hysteria2 reads 94–95 % against the reference's 96–97 % since the pacer was charged once
(2026-09-21, below), with the reader and writer threads this plan asked for in place; the REALITY row
did not reproduce (91–95 % on both, also below). The rest of this file is kept as it was written.

Every other divergence found on the wire has been closed or ruled out. This one is not a constant,
and it showed on BOTH planes, from the same cause — as it was measured then.

## What was measured, 2026-09-19/20, and by what

| plane | metric | reference | this client | stand |
|---|---|---|---|---|
| Hysteria2 | datagrams arriving back-to-back (<50 µs) | 91–93 % | 86 % | `test/hystand/loss.sh` |
| REALITY | write-to-write gaps under 1 ms, 300 KB upload | 91–93 % | ~~82 %~~ not reproduced, see below | `tools/vendorcap/wireshape/run.sh` |
| REALITY | bytes taken per read from the client | 27 279 avg, 57 344 max | 9 539 avg, 34 of 41 reads exactly 8 KB | the same, tracing `read` |

⚠️ **2026-09-21: the REALITY row does not reproduce.** On a stand that starts clean — it had been
leaving each run's server and clients alive, and every tool here listens with SO_REUSEPORT, so a second
run in one container was served partly by the first; see the kill in `wireshape/run.sh` — the upload
gaps under a millisecond are 91–95 % for this client against 91–95 % for the reference, and the same
for the build of 19 September that the 82 % was written from (three runs: 95 · 93 · 91 %).
The pause every five writes is not there. Where the 82 % came from is not known; what is known is
that the stand could not be trusted to report it.

The last row is the mechanism, and it is a feedback loop rather than a constant:

1. This loop alternates — read, frame, write, then back to `epoll_wait`.
2. On the way back, little has accumulated in the client's socket, so the next read is small.
3. A small read shrinks the read-vector ladder (`rv_adjust`), so the next read is capped smaller.
4. Smaller reads mean more trips, and each trip is another chance to wait.

The reference has the same ladder — `cur = n >= cur ? cur * 2 : n`, capped at 8, is
`allocStrategy.Adjust` verbatim — and the same one-at-a-time copy loop
(`vendor/Xray-core/common/buf/copy.go:91-107`). What it does not have is the trip: a goroutine sits
blocked in `ReadMultiBuffer`, so it is woken by the first byte and has usually accumulated more by
the time it looks. Its ladder climbs to 7–8 buffers; ours collapses to 1.

⚠️ Which is why the obvious repairs are all wrong, and each was measured before being dropped:

* relaxing `up_n == 0` to allow two reads in flight — the reference never has two in flight either;
* growing `LC_GSO_BATCH` or `HY_READ_ROUNDS` — measured, and past four rounds it makes the shape
  worse, not better (bigger bursts, longer gaps);
* changing the ladder — it already matches the reference exactly.

## The shape proposed

One thread whose whole job is the blocking read, mirroring the goroutine the reference blocks in.
Everything else — ngtcp2, the record layer, Vision, the session table, every timer — stays in the
loop thread and stays single-threaded, because that is where the invariants live and none of them
are prepared to be shared.

    loop thread (today's code, unchanged in structure)
        owns: sessions, ngtcp2, TLS, Vision, timers, all writes
    reader thread (new)
        owns: nothing but a blocking read into a staging buffer per session
        hands over: bytes and a count, under one mutex per session
        wakes the loop: one pipe (`reader_wake`), a byte per event, level-triggered

The reader thread does NOT frame, does NOT touch the queue the writer uses, and never calls into
ngtcp2 or the record layer. It reads into a buffer the loop hands it and says how much; the loop
picks it up on its next turn and does everything it does today from there.

## What it costs, and the numbers to check before believing it helps

* one thread, stack pinned small (`pthread_attr_setstacksize`) — musl puts pthread in libc, so the
  link line does not change;
* one mutex and one staging buffer per session — sized, like everything else here, from
  `UP_WORST_PER_READ`;
* RSS. Today's live figure on the router is 2296 kB with 366 tunnels served; anything that moves
  this by more than a few per cent is not worth the shape it buys.

## The order of work, so that each step can be judged on its own

1. The measurement that will judge it, first: `wireshape` already reports read sizes and gaps, and
   `loss.sh` reports density. Both baselines are recorded above.
2. The reader thread on the Hysteria2 uplink only — the queue there is a pure byte pass-through with
   no framing, so the thread's contract is `read()` and nothing else.
3. Measure. If the density does not move, stop: the story above is wrong and no more threads go in.
4. Only then the REALITY uplink, which is where the framing is and where the risk is.

⚠️ Nothing about this ships to a router until step 3 has a number, and the mutation controls in
`test/hystand/README` still fail the way they are supposed to.

## Step 2 is done, and step 3 says STOP — 2026-09-20

The reader thread is in (`src/net/reader.{c,h}`), on the Hysteria2 uplink only. What it measured:

| | before | after | reference |
|---|---|---|---|
| 32 MB up and back, clean path | 6.68–7.42 s | **4.86 s** | — |
| datagrams back-to-back (<50 µs), 25 ms path | 86 % | **86 %** | 93 % |
| 16 MB up and back, 25 ms path | 1.43 / 0.88 / 0.74 s | 1.27 / 0.63 / 0.67 s | 1.09 / 0.73 / 0.66 |
| commonest run of datagrams | ~900 × 14 | 1639 × 14 | 2, 3, 4 |
| write loop passes ending dry | 72 % | 71 % | — |
| text segment | 707 979 | 710 825 (+2 846) | — |

Correctness: all nine scenarios of `test/hystand/run.sh` pass byte for byte, including four
concurrent streams, the idle close and the whole reconnect lifecycle. The mutation control on the
reader's own bound — deleting its "no room" check — kills the first scenario with a broken pipe, so
the one invariant the thread owns is covered by a stand and not only by reading.

**The density did not move, and the rule written above was that this stops the work.** It is kept
to the letter: no thread goes anywhere near the REALITY plane on the strength of this.

What the numbers actually say, which is not nothing: on the Hysteria2 plane the thread bought a
third more throughput on a clean path and closed the delivery-time gap, but the SHAPE on the wire is
unchanged. That is consistent, in hindsight, with where each plane's evidence came from — the read
sizes that started all this (9 539 against the reference's 27 279) were measured on REALITY's
`tcpbig`, and the Hysteria2 read path had already been rounded to four bufferfuls per event the day
before, so its read side was the half that was least starved. The density on that plane is decided
by what the write loop has ready when the pacer lets it go, and the counters say that is unchanged:
71 % of passes still end with nothing left to write.

So the story is not disproved and not confirmed. It is untested where it was measured. Whether the
REALITY plane gets the same treatment is a decision with the same evidence in front of it as before,
plus one fact that was not there yesterday: the thread costs 2.8 kB of text, no new buffers, and it
did not break anything a stand can see.

### And then the feed side was chased to the end, which settles the Hysteria2 half

Two more measurements, both on the impaired path, both after the thread:

* **The thread did cure the starvation where there was any.** On the clean path the write loop went
  from 71 % of passes ending with nothing to write to **5.7 %** — the rest now stop on the pace,
  which is the reference's own reason to stop. Throughput followed: 32 MB in 4.05 s against 6.7–7.4.
* **On the delayed path the queue was the next cap, and lifting it changed nothing that matters.**
  There the reader saturates `UP_QUEUE_SIZE`: feeds averaged 18 033 bytes against a queue of 18 693,
  which is one GSO batch, after which the write loop empties and goes dry. Raising the queue by
  24 KB doubled the feed to 37 533 bytes and cut the passes by a third — and the density stayed at
  **85 %**, inside the run-to-run noise of the 86 % it has been since the day before.

So three independent changes on the feed side — four read rounds per event, a thread that reads
continuously, and a queue twice the size — all land on 85–86 % against the reference's 92–93 %.
⛔ The feed is not what the density is about, and nothing more should be spent there. What is left is
the write side: what ngtcp2 has ready when the pacer lets a packet go, and in what order it emits.
That is a different investigation, with different stands, and this document does not open it.

## 2026-09-21: the write side got its thread, and the reader's teardown was wrong

**A second thread, on the Hysteria2 plane only: the writer of the send queue** (`src/quic/sendq.{c,h}`).
It is quic-go's own arrangement — `Send` puts a batch on a channel of eight and a goroutine writes it
(`vendor/quic-go/send_queue.go`) — so this is the reference's algorithm, not a tuning. What it bought
was measured on the router, where it could be, and not on the stand, where it could not:

| | stand, one way, back to back | Xiaomi 4A, upload | Xiaomi 4A, CPU per byte |
|---|---|---|---|
| one thread | 86–91 % | 2.11–2.33 MB/s | 1 |
| with the writer | 89–90 % | 2.45–2.56 MB/s | +17 % |
| reference | 96–97 % | — | — |

On the x86 stand a batch took 218 µs to pack and 32–36 µs to send, so there was nothing to overlap.
It was first blamed on the cipher (portable AES-GCM here against Go's AES-NI), and the stand was made
fair — ChaCha20 on both sides, the reference on plain Go — to take that out. The packing stayed at
173–200 µs, and clocks on the whole iteration found two thirds of it in `lc_qtx_run`, walking the
list of blocks in flight from the head on every packet. With that fixed (`src/quic/txbuf.c`) a batch
packs in 54 µs and the runs of fourteen are gone; the density moved from 90/91/89 % to 90/92/92 %
against the reference's 96–97 %. One run suggested the controller — the reference seemed to stay in
BBR's STARTUP — and two traced runs did not reproduce it: both leave STARTUP, after 20–36 rounds
either way. ~~What is left is not known.~~ It was found the same afternoon, and it was not
concurrency at all: the write loop charged the pacer a second time for every data packet ngtcp2
had already charged through the controller, so the client kept half the pace it was set. Charged
once, the stand reads 94–95 % against the reference's 96–97 %, and the holes in the
acknowledgements match the reference's. `test/hystand/loss.sh` has the account.

**And the reader's teardown had a use-after-free** that this document's plan called "the only place a
bug here would be fatal". The removal went through the stage's lock and cleared an `active` flag,
and a ready event the reader already held for that stage was supposed to find the flag cleared —
but the flag is in the memory being freed. It crashed the service on the router (SIGSEGV in
`pthread_mutex_lock` called from `reader_main`), and procd restarted it without anyone learning of it.
`lc_reader_del` now also waits for the reader to finish its current batch, and `test/reader` fails
without that wait every time.

## 2026-09-29: the other half of io.Copy — the Write to the client — got a thread, and it was not taken

What asked for it: on the MT7621 a Hysteria2 download held one core at 94 % (user 65, system 15,
softirq 14) while the other three sat 85–90 % idle, so the loop thread was the ceiling, and the
Write to the client is work the reference's connection loop never does — `io.Copy(conn, rc)` runs in
a goroutine of its own (vendor/hysteria/app/internal/tproxy/tcp_linux.go:64-67).

What was built: a writer thread in the reader's shape (own epoll, EPOLLONESHOT hand-over carrying
the stage, synchronous removal past the thread's batch). The Read stayed on the loop thread — the
take and the credit touch ngtcp2 — and its bytes were copied into a 32 KiB chunk, as copyBuffer
copies them, and handed over. All of test/hystand/run.sh passed byte for byte.

What it measured on the router, three 100 MB downloads per leg, the flash build before and after
in the same window (a server in a German data centre, through the live tunnel):

| | seconds per 100 MB | CPU seconds per 100 MB |
|---|---|---|
| one Read at a time (io.Copy's rule) | 21.4 · 21.4 · 21.9 | 22.2–22.6 |
| two chunks in flight | 20.4 · 20.8 · 22.3 | 21.5–22.7 |
| no thread, both windows | 19.6–20.6 (22.8 once) | 19.6–21.7 |

With one chunk the loop made one Read per stream per turn and the next waited for the writer's
wake, so neither core ran full (about half each) — the pair was serialised, not offloaded. Two
chunks took that away and the speed came back to level, but the CPU did not: the copy, the hand-over
and the extra turns cost what the Write had cost. On the x86 stand the same build was level on time
and 4 % dearer on CPU. The patches are not in the tree; what the loop does is unchanged.

So of the three threads the reference's arrangement suggests, two are in (the reader of the
client's uplink, the writer of the send queue) and two have been tried and not taken (the reader of
the node's datagrams, G6; this one, G5). The receive path — Salamander, recvmmsg, ngtcp2 and its AEAD
— is where the core goes, and none of it can leave the loop without a hand-over per packet.

## 2026-09-29: the receive path went to the other cores after all — opened ahead, not handed over

The paragraph above ends on "none of it can leave the loop without a hand-over per packet". That is
true, and it is why G5 and G6 failed: a hand-over per datagram costs about what the work costs on
this processor. The maintainer asked again ("~1.3× is not nothing, and ngtcp2 is patched already"), and the
way out was not to hand datagrams over but to hand over BATCHES, and to leave ngtcp2 where it is.

What was built (`src/quic/rxopen.{c,h}`, the hint in `src/quic/qcrypto.c`, patches/ngtcp2/0034):

* the loop reads thirty-two datagrams, eight to a `recvmmsg` as before, and hands the batch to
  threads — one fewer than the processors online — which take Salamander off, header protection off
  and open the AEAD, with copies of the 1-RTT receive keys made from the same key bytes;
* meanwhile the loop feeds ngtcp2 the batch before, datagram by datagram, exactly as it used to;
* ngtcp2 still opens every packet itself, through its hp_mask and decrypt callbacks, and those
  answer from the threads' result only when every input they are given is the one it was computed
  from — the very sample and ciphertext bytes, the key's algorithm and bytes, the nonce, the header.
  Otherwise they compute as always. So nothing ngtcp2 decides, and nothing on the wire, changed;
* 0034 adds one read-only accessor to ngtcp2 — the key, IV, phase, header protection context and
  largest packet number a short header is opened with — because the IV and the largest number live
  inside the connection and the threads cannot build the nonce without them.

It is not the reference's shape — quic-go opens packets in the connection's goroutine — and it is
recorded as DIVERGES O2, the maintainer's decision of 2026-09-29.

What checks it: `test/rxopen` builds packets as the node does, for all three suites, and holds every
answer the callbacks give with a hint to the answer they give without one, byte for byte — including
a tag that does not verify (refused, output wiped), a hint made with a key since replaced, a packet
number decoded against another largest, a changed key phase, a sample, header protection key,
ciphertext or header other than the hint's, numbers that cross 2^8, 2^16 and 2^24; and 200 batches opened by the threads
against the same datagrams opened alone. `test/hystand/run.sh` against the reference server passes
whole. The summary line on SIGUSR1 says how many packets were answered from a hint.

What it measured, on the MT7621 against a LAN node (the reference server on the home server, with
Salamander and ChaCha20 as the live node chooses, so that the processor and not a path is the
ceiling; 100 MB downloads, six per variant, alternating):

| | seconds per 100 MB | CPU seconds per 100 MB |
|---|---|---|
| no threads | 17.3 | 18.3 |
| one thread | 12.4 | 21.1 |
| two threads | 11.9 | 25.6 |
| three threads | 11.5 | 28.4 |
| three, awake 200 us after each batch | 11.6 | 30.0 |
| three, asleep at once | 11.7 | 27.8 |

48 → 70 Mbit/s with every core taken. The threads sleep as soon as they run out — staying awake bought
nothing — and the text grew by 116 bytes.

The final build, measured once more against the build without threads on the same stand, six downloads each: 17.9 s
and 18.8 CPU seconds without threads, 11.1 s and 27.7 CPU seconds with them — 47 → 75 Mbit/s; the
peak resident set grew from 3.0 to 3.4 MB.

On the AX3000T (two Cortex-A53 cores, so one thread; the same stand, AES off on the server so the
node picks ChaCha20 as the live one does; three downloads each):

| | seconds per 100 MB | Mbit/s | CPU seconds per 100 MB | peak resident set |
|---|---|---|---|---|
| no threads | 4.03 | 208 | 4.09 | 6–8 MB |
| one thread | 2.92 | 287 | 4.32 | 9 MB |
| hysteria v2.12.3, the reference client | 3.84 | 218 | 4.83 | 24 MB |

Before this the reference client was ahead of ours by a few per cent on this box; now ours is ahead
by a third, still with less processor per byte than the reference spends.

## 2026-09-29: and the REALITY plane's records the same way — O3

REALITY was left alone above for a reason that held: every connection is its own TLS stream, the
workers already put different connections on different cores, and the reference does no more — uTLS
opens each record in the goroutine that reads the connection. What it leaves on the table is ONE
connection. Measured the same evening through the live node on the MT7621: one download 27–28
Mbit/s with one core at 86–95 %, two at once 43–48 — and the AEAD bench on the same box puts
AES-128-GCM's opening at 182 ms a megabyte, so at 28 Mbit/s two thirds of that core is the cipher.
HTTPS does not escape it: Vision's direct copy is the node's to announce, and with a target like
that server the reference server announces it on about one connection in three (the reference client
got it on 3 of 9 through the stand, this one on 1 of 10); on the rest the stream stays framed and
encrypted to the end.

The maintainer said "do it", and it is O2's design over records instead of datagrams (`src/tls/recopen.{c,h}`):

* when a read leaves several whole records in hand, up to sixteen are handed to threads — one fewer
  than the processors online, a pool per worker, started after the fork — which open each with a
  key of their own, built from the same bytes (`lc_record_key` keeps them now: an mbedTLS context
  cannot be copied) and the sequence number that record will have;
* the loop delivers the records in order exactly as before, and node_open asks the pool first: an
  answer is given only when it was made from these very inputs — the same record at the same
  place, the same length, the same sequence number, algorithm, key and IV, the same room to open
  into — and only when the record opened. A KeyUpdate among them moves the key and the rest are
  opened by the loop; a record that does not open is opened by the loop, which refuses it with the
  alert it always did;
* records_ready takes the records from an offset and moves the buffer once, at the end, after the
  threads have let go of it — it used to move it after every record;
* the socket is read in the reference's sizes — see the section below: the first version grew a
  session's buffer to four records and read that much, and that was a difference on the wire;
* the loop waits for a record a thread is opening a hundred turns, then on a futex. Spinning with
  sched_yield instead, the first version, gave the same speed for three quarters more processor.

What checks it: `test/recopen`, every answer held byte for byte to lc_record_unprotect with a key of
its own, on all three suites, every size from nothing to the largest and every inner type, and none
given for a broken tag, a key that moved, a sequence number the loop moved, another room, a record
nobody handed out; nothing handed out for a TLS 1.2 key, another outer type, a record not whole;
then 300 rounds with the loop not waiting and stopping part-way. The nodealert stand against the
reference client, 50 scenarios of 51 the same — `huge` differs on HEAD too, and is not this.

On the MT7621 against the LAN stand (the reference Xray server, 100 MB over plain HTTP, one
connection, three rounds alternating):

| | seconds per 100 MB | Mbit/s | CPU seconds per 100 MB |
|---|---|---|---|
| the build then installed | 25.3–25.8 | 32.8 | 25.3 |
| O3, spinning while it waited | 15.8–16.0 | 52.8 | 45 |
| O3 | 14.3–14.4 | 58.4 | 37.3 |

87.7 % of the records were answered from the threads; the first of each read is the loop's. The
processor seconds count both threads of a hyper-threaded core in full; how much of the difference
that is, and how much is the hand-over itself, was not measured.

And through a live server (REALITY, the router's own account; 100 MB from a German data centre over
plain HTTP; the new build bind-mounted over the installed one, two rounds each, alternating):

| | one download | two at once | CPU seconds per 100 MB, one download |
|---|---|---|---|
| the build then installed | 28.2–32.2 s, 27.6 Mbit/s | 33.6–38.7 s for both, 43–50 Mbit/s | 29 |
| O3 | 16.1–16.6 s, 51.4 Mbit/s | 29.1–31.8 s for both, 53–58 Mbit/s | 38.5 |

89–90 % of the records answered from the threads. Two downloads at once gain little: the workers
already had them on two cores, and with both pools busy all four hardware threads are.

## 2026-09-30: the node's socket read in the reference's sizes — and what that took from O3

The nodealert stand had one scenario that differed from the reference, and on HEAD as well as with
O3: `huge`, a record header over 2^14 + 256 on a fresh connection. Both clients answer
record_overflow; the reference's connection then goes out with a reset and this one's with a FIN.
The reason is how much each had taken from the socket. uTLS reads into rawInput, a bytes.Buffer,
through readFromUntil — Grow(needs + MinRead), then reads of the buffer's whole free capacity until
`needs` have come — and on a fresh connection that buffer is 576 bytes: it read 576 of the 16 646
and closed with the rest unread. This client, reading a record's room and later four records', had
them all.

So every read of the node's socket now asks for what the reference's would, from the handshake to
the last record: `src/tls/rawin.{c,h}` keeps rawInput's shape — offset, length, capacity, Go 1.27's
bytes.Buffer growth and the allocator's size classes — and node_fill reads by it, in the handshake
(which is now fed from the session's buffer, the machine asking its exact counts as before), in a
spare, in the spider and on an open tunnel. `tools/rawin` runs a real bytes.Buffer with uTLS's
readFromUntil copied from the vendor tree, on amd64 and 386 alike, and `test/rawin` holds the model
to it: 440 streams, 111 369 reads, every size asked and every buffer's shape at the end the same, and
the rounding for every length from 65 to 70 000. nodealert: 51 scenarios of 51 the same, `huge`
included. Mutants 6 of 6 in the model, 4 of 4 in lc-tunnel through the stand.

It costs O3 its batches. A read of the reference's size brings two records of a download, sometimes
three, and a thread can only open what a read has brought; reading further ahead than the reference
would is the very difference just removed. On the MT7621, 100 MB over plain HTTP, one connection:

| | LAN stand | through the live node |
|---|---|---|
| the build then installed | 25.7–26.9 s, 32 Mbit/s | 29.3–31.5 s, 27 Mbit/s |
| O3 reading four records at a time | 14.3–14.4 s, 58 Mbit/s | 16.1–16.6 s, 51 Mbit/s |
| O3 reading as the reference reads | 18.0–19.6 s, 45 Mbit/s | 21.4–23.5 s, 37 Mbit/s |

Half the records are opened ahead — the second of each pair; the first is the loop's. Two downloads
at once are where they were: the workers carry them on separate cores either way.

⚠️ Measuring pairs through this node on 30.09 turned up downloads that never started — curl's 000
after fifteen silent seconds. Every one was a connection still in its handshake with not a byte from
the node. Bursts of twenty requests at once, through the service, answered 9, 14, 2, 4, 2, 2 with
the installed build and 4, 2, 2, 4, 2, 2 with this one: the node (dest avito) stops answering
parallel handshakes, and does so worse the harder it is asked. A download that stops before its
first byte on this plane is to be looked for there first. One stop in the middle of a download —
100.6 MB of 104.9 after 397 s, 30.09 07:1x — was not seen again in the forty-odd pairs after it,
and is not explained.

## 2026-09-30: O3 reads ahead again, and the reference's reads follow in the shadow

Decision of the maintainer, 30.09: the base is done, and for speed the client may step away from the
reference — as a row O in DIVERGENCES.md, marked in the code and measured — provided nothing seen on
the wire changes: bytes, sizes, order, a reset against a FIN.

What reading in the reference's sizes kept on the wire was one thing: how a connection closed with
bytes unread goes out. The kernel sends a reset when the socket still holds bytes nobody read, and
the reference closes with bytes in its socket exactly when its reads have not reached them. So on an
open tunnel, where threads open records ahead, the socket is read a bufferful at a time again — up
to four records, RX_BIG — and `rin`, the model of uTLS's rawInput, is no longer what sizes the reads
but what the reference would have read by now: readRecordOrCCS's readFromUntil for the header and
for the whole record runs against the bytes already in hand (rin_until), each of its reads given
what it asks for or what is there. What has been read past it is `rin_ahead`. A session closed with
`rin_ahead` above zero is closed with SO_LINGER {1, 0} — a reset, which is what the reference's
close is with those bytes still in its socket; with none ahead, the kernel decides for both, as
before. After the announcement of direct copy the reference reads the socket raw and takes what was
read ahead as its next bytes, so nothing is ahead any more. The handshake, a spare, the spider and a
single processor read in the reference's sizes as before (node_fill).

nodealert: 51 scenarios of 51 the same. ⚠️ `huge` among them proved nothing about this: it runs
eleventh, before any read of the process has brought two records, so the threads do not exist yet
and the reads are still the reference's own. A mutant that dropped the reset lived through it. So
the stand has `hugeahead` now — the same bytes, run last, by which time the client reads ahead — and
wireshape counts every SO_LINGER this client sets on a connection to the node, which must be none:
all its downloads are read to their end. Mutants, in a copy of the tree, through nodealert (none,
huge, closeslow, close, hugeahead) and wireshape: the control lives; no reset at the close (killed
by hugeahead), the model never fed (closeslow, and two resets in wireshape), the model fed a whole
read at once (hugeahead) are killed. The fourth, direct copy keeping what was read ahead, lived at
first: on loopback the record announcing direct copy is always the last thing in its read, so
nothing was ahead of the model when it came. wireshape now has a fourth tunnel whose reads of the
node wait 20 ms each (tools/vendorcap/wireshape/slowread.c, LD_PRELOAD), and two TLS downloads
through it — the second starts with the process already reading ahead — so the announcement and
the raw bytes behind it arrive in one read; the mutant closes that connection with a reset and the
stand fails, the real build passes (three runs). Four of four, and the control lives.

On the MT7621, the LAN stand (vendored Xray v26.9.9 on the LAN box, 100 MB over plain HTTP behind
it, -t mode beside the live service), four alternating rounds:

| | seconds | Mbit/s | CPU ticks | records opened ahead |
|---|---|---|---|---|
| O3 reading as the reference reads | 17.2–18.5 | 45–49 | 2 864–3 121 | — |
| reading ahead, the reference in the shadow | 14.3–14.7 | 57–59 | 3 699–3 732 | 44 889 of 51 251 |

— which is where O3 reading four records at a time stood on the same stand (14.3–14.4 s) before the reads were made the
reference's. The live server could not be measured: the MT7621 router was on the Hysteria2 plane.
