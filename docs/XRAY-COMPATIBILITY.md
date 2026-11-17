# Xray interoperability

## Reference candidate — 10 November 2026

The current source reference is **Xray v26.11.9**, revision
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`, with REALITY
`4bb46b2afd8b4f1f082fbaccae34fd3c7a3f8973`, uTLS `a13c59ffe98b`
and x/net v0.62.0. Its client version stamp follows this reference.

The upgrade ports uTLS's TLS 1.3 ML-DSA CertificateVerify acceptance and
failure text, its fragmented-read AvailableBuffer loop, and internal_error
for an offered GREASE group with no key exchange. Source anchors are
`utls/auth.go:verifyHandshakeSignature`, `conn.go:readFromUntil`,
`handshake_client.go:verifyServerCertificate` and
`handshake_client_tls13.go:establishHandshakeKeys` in the pinned vendor tree.

Go-generated ML-DSA cases cover all three parameter sets, valid signatures,
corruption, truncation, wrong keys, wrong signing context, and the reference's
handling of a different ML-DSA scheme name. Both pinned Hysteria profiles
continue to reject these schemes. The read model agrees with the Go 1.27
amd64/386 oracle on 440 streams and 111369 reads.

Hysteria retains its independent app/v2.13.0 and uTLS v1.8.2 references.
The shared fingerprint tool source now builds as `fp` for Xray and
`fp-hysteria` for Hysteria, with separate module files and toolchains.
Historical measurements below do not qualify the new candidate. Final SDK
packages, hardware switching and production publication require new receipts.

The local candidate passed the full `make check`, all four MIPS/AArch64
cross-build variants, and the actual server image's C-client compatibility
gate. OpenWrt 25.12.5 AArch64 APKs passed disposable-root install/upgrade,
credential preservation and packaged-binary execution under QEMU. OpenWrt
24.10.8 MIPS IPKs passed payload inspection and packaged-binary QEMU execution.

Both packaged dual-plane binaries also ran on physical AX3000T and 4A devices:
REALITY, Hysteria without obfuscation and Hysteria Salamander, each with one
and four workers. Each case checked four concurrent 1 MiB HTTP/TLS payloads,
64 nonce-checked UDP echoes and complete owned-process cleanup. The isolated
peer recorded 48 payloads and 768 unique UDP echoes across both devices.
Configuration, interfaces, boot identity and policy rules stayed unchanged;
the AX3000T's existing AWG path still returned HTTPS 200 afterward.

These are bounded data-path receipts for the recorded dirty candidate,
not a throughput comparison, package installation on devices, production API
delivery, service switching or a final signed release qualification.

## Qualified reference — 5 November 2026

The behavioral reference for these measurements was **Xray v26.10.31**, revision
`a4a3dff5b20c2faae567b742c172c7b95e75c083`, built with Go 1.27.3.
REALITY is pinned to `83f621788ca88b83179810b12baa7ae518aacb83` and its HTTP/2
dependency to x/net v0.61.0. Hysteria's separate QPACK oracle retains x/net
v0.58.0. ClientHello fingerprint defaults remain unchanged.

## Local package candidate — 6 November 2026

The candidate is prepared for local qualification. It has not been deployed as
a router package or approved for production. Earlier hardware measurements
remain attached to their recorded executable hashes.

The local checks include the full `check-spider-behavior` gate, four MIPS/AArch64
cross-build variants, 44 configuration/package/readiness tests and the argument
suite under ASan/UBSan. Actual SDK MIPS packages pass offline install/fixture
upgrade and execution under qemu, including nonblocking fingerprint FIFO
refusal. The x86 OpenWrt VM runs real APK hooks, procd, ubus and TPROXY, verifies
TCP/TLS/UDP against the pinned Xray, and restores configuration and all three
default secrets into a fresh boot with identical bytes and mode 0600.

Readiness excludes a supervisor retaining a shared TCP socket without workers,
unpolled sockets and stopped workers. A no-consumer interval preserves
interception and returns a startup error; recovery restores service. TCP bytes
retained in the kernel backlog may reach the backend after recovery, and are
checked separately from delivery before recovery. Public fingerprint reads
reject special files and I/O errors without accepting a valid prefix.

Before a package release, the remaining work is:

1. Build and qualify packages from the final Git revision. The automatic build
   stamp changes executable/APK hashes after a commit; retain receipts for the
   rebuilt artifacts rather than relabeling an earlier dirty-tree package.
2. With separate hardware authorization, install/upgrade those exact packages
   on the MIPS and AArch64 target devices and verify physical reboot and actual
   firmware sysupgrade. Diskless configuration backup/restore is not flashing.
3. Run the long mixed-workload/reclamation matrix on those same executables and
   repeat matched reference throughput measurements. Use identical hardware,
   path and configuration; historical measurements are not new package results.
4. Review the resulting receipts before approving a release. The controlled
   predecessor fixture is not evidence of migration from every historical
   released package. RAM observations remain diagnostic; flash is the resource
   acceptance threshold.

The implemented interception scope remains IPv4 TCP 80/443 and optional UDP
443. IPv6, DNS and unselected traffic follow the routing described in
[CONFIG.md](CONFIG.md); this is not a full-device kill switch. The existing
[divergence registry](../DIVERGENCES.md) remains authoritative for intentional
differences. No new production fingerprint, ports, credentials or trust roots
are introduced by this candidate qualification.

## Completed local checks

The candidate is freshly built in `docker/Dockerfile`'s build environment.
All workload runs use an isolated container with networking disabled and
loopback listeners. No installed router or remote server is changed.

Two independent matrices were retained: the old-pin baseline and the upgraded
candidate. Each uses three counterbalanced rounds running the full Xray client and LiteClient with
one and four workers against the same new Xray server. Each role completes
plain and TLS 1.3 payload cases, with one and four simultaneous streams:

| Check | Completed result |
| --- | --- |
| Bulk cases | 36, each delivering 32 MiB with SHA-256 and server-receipt verification |
| Delivered bulk payload | 1152 MiB |
| UDP/XUDP | 576 byte-checked echoes, four concurrent sockets per phase |
| Four-worker startup | All four worker identities appear in each candidate phase log |
| Client/server shutdown | Expected process exits and successful owned-process cleanup |

In the upgraded run, the server accepts only REALITY client version 26.10.31.
All four CLI entry points share the version macros checked against the pinned
`core/core.go`; the authentication-vector generator independently reads that file.
An independent validator rechecks payload hashes, case coverage, all worker
identities, input hashes, copied runner sources and closure captures.

These are interoperability checks, not device throughput measurements. They do
not replace the existing matched hardware results or a long mixed-workload soak.
The initial stand lacked ALPN on its TLS target: even Xray-to-Xray failed before
any measured transfer. The target now offers `h2` and `http/1.1`. Those failed
starts are retained separately and are excluded from the completed matrix.

## Vision close: measured before and after

Xray v26.10.31's `proxy/proxy.go::SuppressOuterCloseNotify` is invoked when
`VisionReader.ReadMultiBuffer` or `VisionWriter.WriteMultiBuffer` enters direct
copy. `transport/internet/reality/reality.go::UConn.Close` then closes the raw
connection without adding an outer TLS close notification.

The old v26.9.9 implementation constructed an outer close notification after
direct copy. `src/cmd/lc-tunnel/main.c::session_close` now suppresses it when the
reader or writer has actually entered raw copy. Announcing the writer transition
alone does not suppress closure. A transparent loopback relay observes:

| Client | Captures per run | Old candidate: trailing 24-byte record | Upgraded candidate |
| --- | --- | --- | --- |
| LiteClient, one worker | 15 | 15 | 0 |
| LiteClient, four workers | 15 | 15 | 0 |
| Xray v26.10.31 | 15 | 0 | 0 |

The relay records encrypted bytes; record length alone does not decrypt an
alert. The interpretation follows the two implementations' close paths. The
old payload checks passed despite the difference, so successful transfers alone
must not be presented as proof of identical close behavior.

## Reference-dependent regression checks

The documented Docker build completes and `make -j4 check-spider-behavior`
passes offline. This includes the ordinary C suites, 90 checkpoint tests,
Go certificate parsing/verification/policy comparisons, fingerprint and pin
gates, all four MIPS/AArch64 builds with Hysteria disabled/enabled, and ARM64/x86
cryptography execution checks. The paired close and flow oracles pass too.
Stripped binary sizes remain 921,732 / 1,449,108 bytes on MIPS and
788,440 / 1,116,240 bytes on AArch64 (REALITY only / with Hysteria).

- `tools/visionclose/main.go` invokes the pinned Xray `VisionReader` and
  `VisionWriter`, observing `SuppressCloseNotify`. Six C cases cover incoming
  raw copy, outgoing raw copy and announcement only on Unix and loopback TCP.
- `tools/spiderclose/flow_test.go` executes the actual Go 1.27.3 transport with
  controlled SETTINGS/WINDOW_UPDATE sequences. Three C observations match lazy
  overflow detection, connection errors and restoration of the initial window.
- `tools/spiderclose/headerbudget/main.go` captures the pinned HTTP/2 Framer's
  independent header/trailer-declaration budgets. Eight small-budget C cases and
  a full-size CONTINUATION boundary use generated reference observations.

Isolated mutation builds restore the old outer-close behavior, eager flow-window
overflow rejection and a shared header/trailer budget in turn. Each is rejected
by its corresponding C regression suite; the working sources are not mutated.

The 18 existing ownership cases, six new Vision cases and eight header-budget
cases also execute successfully on the authorized Mi Router 4A MIPS device,
using temporary files only. Existing hardware reports retain their original
references; fresh upgraded-reference checkpoints are described below.
The loopback matrix does not cover every optional authentication mode. Longer
mixed traffic is checked separately below. No client package is installed.

## Fresh fallback checkpoints

The ordinary host v4 and Mi Router 4A native v4 checkpoints each complete
24 phases and 120 wrong-key retry connections against the new reference.
Both pass their existing 100-us first-request regression budget, with zero
positive regression in all four scenarios. CANCEL/path-selection rates remain
diagnostic. Native execution takes 372 seconds with 371 resource observations;
boot identity, configuration and interfaces match before/after, and temporary
device inputs are removed after evidence retention.

Before interpreting the native distribution, a separate host control runs full
Xray and the protobuf distribution on the same `bigbody`/`gzbody` destination.
All 20 captures have the expected opening SETTINGS, connection window and
redirect request sequence. Executable/input hashes, probe exits, ordinary
process exits and cleanup validate. The distribution is a test adapter, not
a replacement application or a measurement of full-Xray configuration startup.

The controlled destination retains its independent x/net v0.58.0 fixture pin.
Its dependency sums are now committed, seeded into the documented Docker image
and included in the source manifest. Building it offline with `-mod=readonly`
and all 90 checkpoint tests succeeds.

## Fresh Mi Router 4A throughput

A new REALITY-only LAN matrix alternates candidate/reference order in three
rounds and brackets the tunnel with three direct-relay controls. It completes
nine phases and 36 SHA-256/receipt-verified 128-MiB transfers (4608 MiB).
The server requires client version 26.10.31. Each table cell is median
candidate/reference Mbit/s:

| Payload | One stream | Four streams |
| --- | --- | --- |
| Plain | 58.5 / 10.6 | 68.1 / 20.6 |
| TLS 1.3 | 875.0 / 815.0 | 900.5 / 805.5 |

The 658-second run validates executed binary hashes, payloads, receipts, phase
order, monitor completion and cleanup. The temporary web-service pause is
restored; boot/configuration/interfaces match and staged device files are
removed after archiving. Native Xray uses the qualified protobuf distribution.
No new AX3000T throughput result is implied. Historical two-router/Hysteria
measurements remain separate. These rates exclude loader-side TCP/TLS setup
and do not predict internet performance.

## Bounded mixed-workload soak

The final host run lasts over 15 minutes: full Xray, one-worker LiteClient and
four-worker LiteClient each carry mixed traffic continuously for 300 seconds.
It completes 2684 SHA-256/receipt-checked TCP/TLS cases of 8 MiB each and
42,944 byte-checked UDP echoes while repeatedly opening new source sockets.
Each role retains 152 resource observations; the largest monitor gap is
2.047 seconds. All expected client process identities remain present, all four
worker identities are logged, normal stop results match and owned-process
cleanup succeeds. An independent replay validates input/source hashes, case
coverage, payloads, monitor continuity and shutdown. Rates in this soak are not
used as throughput comparisons. RAM has no acceptance threshold; sampled RSS
under source-port churn does not establish absence of leaks.

The first mixed run stopped on a UDP timeout in the one-worker candidate.
That evidence is retained. A separate five-minute candidate replay passed.
The initial capture relay also imposed a 15-second idle disconnect, which
injected an unintended connection failure into an ordinary-traffic soak. The
final relay removes that idle disconnect while preserving the five-second UDP
reply deadline and all payload checks. The timeout does not recur in the final
run, but its original cause is not proven and no client fix is claimed for it.
This bounded host run does not replace an hours-long hardware soak.

## Controlled UDP close and recovery

`tools/vendorcap/nativeclient/udp_lifecycle.py` isolates the fault mechanism in
a loopback-only Linux namespace. Three rounds cover full Xray, one-worker
LiteClient and four-worker LiteClient, each with no injected fault, an injected
TCP FIN and an injected TCP RST. The controls use unique nonce-tagged payloads,
wait for owned UDP listeners (all four worker sockets where requested), and
retain complete PCAPs with no allowed capture drops.

In the completed 27-case control, all 171 mandatory echoes pass across 189
requests. The 18 first packets after injected closes time out in this run:
the same observation occurs with full Xray and both LiteClient worker modes.
Every quiet-period recovery, same-source-port rebind and fresh-source control
then succeeds. These fault-time losses are diagnostic, not an instruction to
add a client retry or change its close policy.

The PCAP independently confirms both injected TCP flags and each accepted
nonce on the client and backend UDP paths. Input/helper hashes, executable
receipts, worker startup, process-group shutdown and cleanup validate. The
retained driver can analyze the archive without the checkout; 111 Python tests
include rejected missing/truncated wire evidence, changed helpers, incomplete
cases, false identities, missing recovery intervals and premature timeouts.

This supplies a reproducible fault-loss mechanism consistent with the pinned
`proxy/vless/outbound/outbound.go::getResponse`,
`common/signal/timer.go::ActivityTimer.SetTimeout` and
`features/policy/policy.go::SessionDefault` close/activity policy. The original
mixed-run timeout has no matching packet capture, so its particular cause
remains unproven. No production client behavior is changed for this finding.

## Native mixed workload and idle reclamation

A separate Xiaomi Mi Router 4A run completes in 1005 seconds. Both one-worker
and four-worker clients perform two epochs: 60 seconds of mixed load followed
by 190 seconds of quiet. This is four active minutes plus expiry observation,
not 16 minutes of continuous traffic. All 96 one-MiB HTTP/TLS downloads and
1536 nonce-checked UDP echoes pass; backend journals independently confirm
every case, TLS mode, payload hash and unique UDP payload.

All four quiet checkpoints retain only the intended listeners. The one-worker
process returns to six descriptors, while the supervisor/four-worker group
returns to 28 descriptors in aggregate, matching their initial observations.
No session socket survives either idle epoch. The 486 one-worker and 484
four-worker resource observations retain the same PID/start-time identities
and complete coverage. Device boot, configuration and interfaces match;
client groups exit, temporary files are removed, and installed services remain
running throughout. RAM observations are diagnostic without an acceptance cap.

The first setup attempt is retained separately: ordinary LiteClient correctly
refused a staged UUID file with permissions broader than 0600, before any
workload. Preparation now stages owner-only inputs and rejects host executables
where native MIPS binaries are required. The 132 Python tests include the
permission guard, corrupted/missing echoes, real helper socket ownership,
incomplete monitoring and retained session sockets. Detached replay of the
complete native evidence passes. This remains a bounded correctness/reclamation
check, not a throughput measurement, hours-long soak or release decision.

## Completed long native mixed workload

The frozen original candidate completes a 7965-second Mi Router 4A run. Both
one-worker and four-worker modes perform two 1800-second scheduled mixed-load
windows, each followed by 190 idle seconds. All 2880 one-MiB HTTP/TLS downloads
and 46,080 nonce UDP echoes pass with independent backend receipts. This is two
active hours of periodic bursts plus expiry observation, not continuous bulk
load or a throughput comparison.

All 7595 monitor observations retain stable PID/start-time identities and gaps
no larger than two seconds. All four quiet checkpoints have zero session
sockets; aggregate descriptor totals return to their initial 6/28 for one/four
workers. Boot/configuration/interfaces match, normal exits validate, and owned
temporary device/stand files are removed. RAM observations remain diagnostic.

Original/reviewed archive checksums and three local analyzer replays validate;
a replay with no checkout also passes. Later compiler-conversion and empty
TLS-record fixes have a different binary hash and separate local checks. This
long result remains attached to its frozen candidate; it grants no deployment
approval and no speed or universal leak-freedom guarantee.

## Native follow-up for the record-layer fixes

The MIPS candidate including the conversion and empty-TLS-copy
fixes, separately completes a 1005-second one/four-worker Mi Router 4A check.
All 96 one-MiB HTTP/TLS downloads, 1536 nonce UDP echoes, 970 monitor samples
and four empty-session-socket checkpoints validate. Descriptor totals return
to 6/28, process identities and device state match, and owned temporary files
are removed. Frozen/current analysis and replay without the checkout pass.

After that workload, all 32 record-layer checks also execute on the MIPS
device: RFC 8448 payload/wire vectors and empty TLS 1.3/TLS 1.2 CBC, GCM and
ChaCha20-Poly1305 cases. The current staged/executed client and the separate
test executable are hash-verified. RAM remains diagnostic. This follow-up
qualifies the later binary for the bounded native check; it does not transfer
the earlier two-hour or throughput measurements to it. No package is installed.

## Independent streams during upstream failure

The isolated host `flow_isolation.py` control completes 27 cases: three rounds
of baseline/FIN/RST for full Xray and LiteClient with one/four workers. A victim
UDP transport is closed while distinct UDP, plain TCP and TLS 1.3 neighbors
continue using their original application sockets and backend connections.
All 10,649 neighboring exchanges and 63 mandatory victim echoes pass. The 18
first victim requests after injected closes time out equally for all clients;
recovery succeeds while neighboring traffic continues.

The full-reply deadline stays five seconds. Frozen sources/configurations,
executable identities, backend nonce journals and lossless PCAP verify distinct
upstreams, progress before/after injection, actual victim FIN/RST, no neighbor
close during observation and ordinary process-group cleanup. All 150 Python
tests pass, including rejected hidden reconnects and missing progress/evidence.

This exercises the per-session activity design in pinned
`proxy/vless/outbound/outbound.go::Handler.Process` and
`common/signal/timer.go::ActivityTimer`, mirrored by
`src/cmd/lc-tunnel/main.c::act_set`/`act_update`/`act_fired`. It requires no client
timer/retry change. This is bounded host flow isolation, not additional native
performance evidence, proof of the historical timeout's cause or release approval.

Sources: [v26.10.31 release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31),
[Vision implementation](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/proxy.go),
[REALITY close implementation](https://github.com/XTLS/Xray-core/blob/v26.10.31/transport/internet/reality/reality.go).
