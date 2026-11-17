# Patches to ngtcp2

This directory holds 34 patches against [ngtcp2](https://github.com/ngtcp2/ngtcp2). The client's
Hysteria2 plane runs on ngtcp2, and ngtcp2 as released does not behave on the wire the way the
reference client does. These patches close that gap. Each file starts with a plain-text header
that says what it changes, what upstream did before, and which lines of the reference it follows.
The header is the authoritative description; this file is the index.

## Why ngtcp2 is patched

The reference for the Hysteria2 plane is apernet/hysteria `app/v2.13.0`, whose client runs on
apernet's fork of quic-go. A path observer, or the server itself, can tell two QUIC stacks apart
long before it decrypts anything: by when ACKs are sent, how long the probe timeout is, how many
bytes a packet number takes, where the padding goes, how large datagrams get once PMTU discovery
runs, and above all by the rhythm of the congestion controller. The goal of this client is to be
indistinguishable from the reference, so each of those behaviours is brought into line with what
quic-go (and, for congestion control, hysteria) actually does.

Most patches are that kind of change: they replace an ngtcp2 rule with quic-go's rule, usually for
the client side only, and leave the server paths as upstream wrote them. A few are different:

- 0009 and 0018 add hysteria's congestion control. Hysteria replaces quic-go's controller with its
  own port of Chromium's BBRv1 once the client is authenticated, and runs quic-go's NewReno until
  then. ngtcp2's `NGTCP2_CC_ALGO_BBR` is BBRv2, a different algorithm, so it could not stand in.
- 0014 is the Chrome parrot. Since hysteria 2.11 the reference client imitates Chrome's QUIC stack
  unless told not to, and the parts of that imitation that live in packet layout are here, behind a
  new `chrome_parrot` setting.
- 0010, 0011, 0024, 0025 and 0034 add entry points. Through them the client hands ngtcp2
  something it had no way to receive (0011, a datagram's arrival time), asks it something it
  already computes (0010, 0024, 0034), or has it queue a frame it never sends on its own (0025).
  0034 has nothing to do with quic-go: it lets the client open incoming 1-RTT packets on other
  CPU cores (see `CONCURRENCY.md` at the repository root), and it changes neither what ngtcp2
  decides nor anything on the wire.

None of the patches fixes a bug in upstream ngtcp2 as upstream uses it. Where a header says
upstream "differed", it means upstream made a different, valid choice.

## Base revision

The patches apply to ngtcp2 commit `d7fb3ed0407e1333e4ecbd011fcfd9c16499d5e0`
(`git describe`: `v1.25.0-8-gd7fb3ed0`). This is the `ngtcp2` row of the "Pinned revisions" table
in `docs/BUILD.md`; `tools/vendor/fetch.sh` checks out exactly that, and `make check-vendor` fails
if `vendor/ngtcp2` is anywhere else.

The headers cite code by path and line:

| Prefix in a header | Tree | Revision |
|---|---|---|
| `vendor/ngtcp2/…` | ngtcp2, unpatched | `d7fb3ed0` |
| `vendor/quic-go/…` | apernet/quic-go | `a10df75c` (`v0.63.1-0.20261004180939-a10df75c260c`) |
| `vendor/hysteria/…` | apernet/hysteria | `ca8fbd8` (`app/v2.13.0`) |

A line number in a header is only meaningful at those revisions.

## How the build applies them

The rule is in the top-level `Makefile`, under `NGTCP2_UPSTREAM`:

1. `vendor/ngtcp2` is never modified. Its `lib/` and `crypto/` directories are copied into a
   scratch directory.
2. Carriage returns are stripped from every `.c` and `.h` in the copy, so that a checkout made with
   `core.autocrlf` on Windows still matches the LF patches.
3. Every `patches/ngtcp2/*.patch` is applied in lexical order (`$(sort $(wildcard ...))`) with
   `patch -s -p1 -F0 -N`. `-F0` means no fuzz: a patch whose context does not match exactly stops
   the build with "... does not apply to vendor/ngtcp2 at the pinned revision", instead of landing
   a few lines away from where it was written.
4. The patched `lib/` and `crypto/` are copied to `$(BUILD)/ngtcp2` (`build/ngtcp2` by default)
   and the stamp `$(BUILD)/ngtcp2/.patched` is written last. A failure leaves no stamp, so the next
   build starts from scratch. Changing any patch or any upstream source file re-runs the whole step.

The object list names `lib/ngtcp2_hybbr.c` explicitly, because that file only exists after 0009.

The series is a stack. Each patch is a diff against the tree with every earlier patch applied, and
only the full series, in order, is built and tested. Some patches happen to apply to a clean tree on
their own; that is an accident of where their hunks fall, not something to rely on.

## Applying them by hand

```sh
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
git checkout d7fb3ed0407e1333e4ecbd011fcfd9c16499d5e0
for p in /path/to/lite-client/patches/ngtcp2/*.patch; do
    patch -p1 -F0 -N < "$p" || { echo "stopped at $p"; break; }
done
```

On Windows, clone with `-c core.autocrlf=false`, or strip CRs from `lib/` and `crypto/` first as
the Makefile does.

Two things the patches do not do, because this client never builds ngtcp2 with its own build
system:

- They do not add `lib/ngtcp2_hybbr.c` (from 0009) to `lib/CMakeLists.txt` or `lib/Makefile.am`.
  Add it by hand if you build with CMake or autotools.
- They change the public ABI. 0014 inserts a `chrome_parrot` field into the middle of
  `ngtcp2_settings`, and 0009 adds `NGTCP2_CC_ALGO_HYBBR`. The result must be linked into the
  program that uses it, as this client does, and never installed in place of a system
  `libngtcp2`.

## Checking that they still apply

From the repository root:

```sh
make check-vendor                 # vendor/ngtcp2 is at d7fb3ed0
make build/ngtcp2/.patched        # copies, strips CRs, applies all 34 with -F0
```

The second command stops with the name of the first patch that does not apply. To try the series
on another ngtcp2 revision without touching `vendor/`, run the loop above in a separate checkout at
that revision. The first patch that fails is the one to rebase, and the ones after it cannot be
judged until it is.

To change patch N, apply 0001 through N-1 to one copy of the tree, which becomes the base, and
0001 through N to a second copy. Edit the second copy, regenerate N as a unified diff between the
two (`diff -Naur` or `git diff`), and put its header back on top. Then check that the patches after
N still apply with `-F0`.

## The patches

"Kind" is one of: quic-go parity (ngtcp2's rule replaced by quic-go's), hysteria-specific (what
hysteria does on top of quic-go), Chrome parrot, or API extension (a new entry point the client
calls; nothing changes unless it is called). No patch is a plain upstream bug fix.

Paths in the "why" column are relative to the quic-go or hysteria tree named above. "Upstream" is
explained in the next section.

| # | File | What it changes | Why (reference behaviour) | Kind | Upstream |
|---|---|---|---|---|---|
| 0001 | `0001-keep-alive-like-quic-go.patch` | Keep-alive PING timed from the last packet received, one per silence, and allowed in ack-eliciting packets | quic-go sends at last receive + max(interval, 1.5 PTO) (`connection.go`) | quic-go parity | |
| 0002 | `0002-ack-only-ping-like-quic-go.patch` | A PING added after 19 ACK-only 1-RTT packets in a row, counted rather than timed; none in Initial/Handshake | `MaxNonAckElicitingAcks` (`packet_packer.go`, `internal/protocol/params.go`) | quic-go parity | |
| 0003 | `0003-ack-timing-like-quic-go.patch` | Flat 25 ms delayed-ACK timer, quic-go's immediate-ACK rules, pending ACK rides in every data packet | `internal/ackhandler/received_packet_tracker.go` | quic-go parity | |
| 0004 | `0004-pto-like-quic-go.patch` | Initial PTO 200 ms, backoff capped at 60 s, two probes per timeout, probe count cleared only after address validation | `internal/utils/rtt_stats.go`, `internal/ackhandler/sent_packet_handler.go` | quic-go parity | |
| 0005 | `0005-clienthello-layout-like-quic-go.patch` | ClientHello CRYPTO cut once at the second half of the SNI, that piece sent last, frames shuffled uniformly | `crypto_stream.go`, `packet_packer.go` | quic-go parity | |
| 0006 | `0006-packet-number-length-like-quic-go.patch` | Client packet numbers are 2, 3 or 4 bytes by unacknowledged count, never 1 | `PacketNumberLengthForHeader` (`internal/protocol/packet_number.go`) | quic-go parity | |
| 0007 | `0007-coalesced-padding-like-quic-go.patch` | In a coalesced handshake datagram the leading Initial carries the padding, not the last packet | `packet_packer.go` (`initialPaddingLen`) | quic-go parity | |
| 0008 | `0008-path-mtu-like-quic-go.patch` | Paths start at 1280, padding follows the discovered size, PMTUD is quic-go's binary search without a probe timer | `mtu_discoverer.go`, `internal/protocol/params.go` | quic-go parity | |
| 0009 | `0009-hysteria-bbr.patch` | New `NGTCP2_CC_ALGO_HYBBR` in `lib/ngtcp2_hybbr.{c,h}`: hysteria's BBRv1 and its token-bucket pacer | `core/internal/congestion/bbr/*`, `core/internal/congestion/utils.go` (hysteria) | hysteria-specific | |
| 0010 | `0010-ack-only-when-paced.patch` | Exposes the existing 1-RTT ACK-only writer as `ngtcp2_conn_write_ack_pkt_1rtt` for a caller that paces outside ngtcp2 | quic-go still sends an ACK when pacing-limited (`connection.go`) | API extension | with rework |
| 0011 | `0011-rx-time-like-quic-go.patch` | `ngtcp2_conn_read_pkt_rx` takes the datagram's arrival time; ACK processing, loss detection and the controller use it | quic-go stamps `rcvTime` at socket read (`transport.go`, `sys_conn_oob.go`, `connection.go`) | API extension | with rework |
| 0012 | `0012-crypto-offset-like-quic-go.patch` | CRYPTO data capped at 16 KiB at every encryption level | `MaxCryptoStreamOffset` (`internal/protocol/params.go`, `crypto_stream.go`) | quic-go parity | |
| 0013 | `0013-long-header-length-like-quic-go.patch` | Long-header Length field written as a 2-byte varint instead of 4 | `internal/wire/extended_header.go` | quic-go parity | |
| 0014 | `0014-chrome-parrot-like-quic-go.patch` | `chrome_parrot` setting: first Initial numbered 1, 1250-byte datagrams, Chrome's packet-number rule, no coalescing, chaos-protected Initials | `chrome_parrot.go`, `packet_packer_chaos.go`, `packet_packer.go`; `core/client/client.go` (hysteria) | Chrome parrot | |
| 0015 | `0015-connection-id-change-like-quic-go.patch` | Client moves to the server's first issued Connection ID after the handshake, retires the old one, rotates every 5000-15000 datagrams | `conn_id_manager.go` | quic-go parity | |
| 0016 | `0016-receive-window-like-quic-go.patch` | Receive windows auto-tuned by quic-go's epochs; an update is due once three quarters of the window remain | `flow_controller_base.go`, `flow_controller_connection.go` | quic-go parity | |
| 0017 | `0017-retransmission-order-like-quic-go.patch` | Streams with lost data queued first-in first-out and kept at the front until drained | `framer.go` | quic-go parity | |
| 0018 | `0018-quic-go-reno-until-auth.patch` | hybbr gains a NewReno mode with quic-go's pacer, used until authentication; timer-declared losses reach the controller at once | `internal/congestion/cubic_sender.go`, `internal/ackhandler/sent_packet_handler.go`; `core/client/client.go` (hysteria) | hysteria-specific | |
| 0019 | `0019-loss-detection-like-quic-go.patch` | Fixed packet threshold of 3, losses oldest first, no persistent congestion | `internal/ackhandler/sent_packet_handler.go`, `sent_packet_history.go` | quic-go parity | |
| 0020 | `0020-rtt-estimate-like-quic-go.patch` | RTT estimator in microseconds through float32, ack delay always capped; Retry handled as `ResetForRetry` | `internal/utils/rtt_stats.go`, `internal/ackhandler/sent_packet_handler.go` | quic-go parity | |
| 0021 | `0021-packet-number-skipping-like-quic-go.patch` | Skipped 1-RTT packet numbers on quic-go's schedule (period 256 doubling to 128 Ki) | `internal/ackhandler/packet_number_generator.go` | quic-go parity | |
| 0022 | `0022-payload-like-quic-go.patch` | 1-RTT payload order: ACK, padding, shuffled control frames, STREAM frames with the last one's Length dropped; DATAGRAM placement | `packet_packer.go`, `framer.go`, `internal/wire/stream_frame.go` | quic-go parity | |
| 0023 | `0023-stream-retransmission-like-quic-go.patch` | Lost STREAM data resent frame by frame from a per-stream queue, not merged by offset | `send_stream.go`, `framer.go` | quic-go parity | |
| 0024 | `0024-window-update-due.patch` | `ngtcp2_conn_lc_window_update_due`: says whether MAX_DATA or MAX_STREAM_DATA is due now | quic-go wakes its sender as soon as a read makes an update due (`receive_stream.go`, `connection.go`) | API extension | candidate |
| 0025 | `0025-streams-blocked-like-quic-go.patch` | `ngtcp2_conn_lc_streams_blocked_bidi`: queues STREAMS_BLOCKED once per limit | quic-go's `OpenStream` sends it at the limit (`streams_map_outgoing.go`) | API extension | candidate |
| 0026 | `0026-key-update-like-quic-go.patch` | Client initiates key updates after 100 packets, then every 100000 | `internal/handshake/updatable_aead.go` | quic-go parity | |
| 0027 | `0027-close-like-quic-go.patch` | CONNECTION_CLOSE during the handshake sent at every level still keyed, in one datagram padded by the Initial | `packConnectionClose` (`packet_packer.go`) | quic-go parity | |
| 0028 | `0028-confirm-on-1rtt-ack-like-quic-go.patch` | Client confirms the handshake on an ACK of a 1-RTT packet, not only on HANDSHAKE_DONE | `connection.go`, `internal/ackhandler/sent_packet_handler.go` | quic-go parity | |
| 0029 | `0029-ack-ranges-like-quic-go.patch` | Up to 64 ACK ranges; ACK-of-ACK pruning only in the application space | `MaxNumAckRanges` (`internal/protocol/params.go`, `internal/ackhandler/received_packet_history.go`) | quic-go parity | |
| 0030 | `0030-ecn-like-quic-go.patch` | ECN marking and validation replaced by quic-go's `ecnTracker` | `internal/ackhandler/ecn.go` | quic-go parity | |
| 0031 | `0031-history-like-quic-go.patch` | ACKs processed against quic-go's sent-packet history, including ACK-only packets and without packets already declared lost | `internal/ackhandler/sent_packet_handler.go`, `sent_packet_history.go` | quic-go parity | |
| 0032 | `0032-pto-probe-like-quic-go.patch` | A PTO probe first requeues the oldest outstanding packet; a 1-RTT PTO skips a packet number | `QueueProbePacket` (`internal/ackhandler/sent_packet_handler.go`, `connection.go`) | quic-go parity | |
| 0033 | `0033-close-like-quic-go.patch` | Transport errors close with quic-go's error code, frame type and reason text; frame and parameter checks in quic-go's order | `packet_packer.go`, frame parser, `connection.go`, `framer.go` | quic-go parity | |
| 0034 | `0034-rx1rtt-keys.patch` | `ngtcp2_conn_get_rx1rtt_keys`: read-only view of the current 1-RTT receive key, IV, header-protection context and largest packet number | none; it serves multi-core receive in this client | API extension | with rework |

Many of the parity patches change only the client path and leave the server code as upstream wrote
it; their headers say so. Others change code a server would share. Either way the patched library
is meant to run as a client, and the tests below only drive a client.

## Upstream candidates

A patch is marked as a candidate only if all of these hold: it is not about imitating quic-go,
hysteria or Chrome; an existing ngtcp2 user sees no change unless they call something new; and it
is small enough to review on its own. Everything else changes default behaviour on purpose, or
hard-codes the reference's constants, and is not something upstream should take.

0024 and 0025 are candidates as they stand, apart from the `lc_` prefix in their names. 0024 is a
read-only query built from two existing internal predicates. 0025 lets an application send
STREAMS_BLOCKED, which RFC 9000 says a sender SHOULD send and which ngtcp2 currently only parses.

0010, 0011 and 0034 are marked "with rework". 0010 is useful to any application that paces
outside ngtcp2, but the function has no declaration in the public header (the client declares it
itself) and would need one. 0011 adds a new entry point, and also changes which timestamp
`ngtcp2_rtb_recv_ack` hands to the controller and loss detection; for packets upstream already
buffers that is a behaviour change, so the two parts would have to be proposed separately. 0034
exposes pointers into connection state for a threading design upstream may not want to support;
it is worth proposing only as a question.

0009 is opt-in too (nothing uses `NGTCP2_CC_ALGO_HYBBR` unless it is selected), but it is a large
port of hysteria's Go code with a second mode added by 0018, and ngtcp2 already ships its own BBR.
It is not marked.

## Groups and dependencies

Textually, every patch depends on the ones before it: they all edit `lib/ngtcp2_conn.c`, and with
`-F0` a missing predecessor usually breaks the context of a later hunk. Removing 0027, for example,
makes 0030 fail to apply, and removing 0024 breaks 0025. The dependencies below are the ones in
behaviour, which is what matters when rebasing or reverting.

### Acknowledgements and timers

Patches 0001, 0002, 0003, 0004, 0028 and 0029. Most headers from 0002 to 0013 name the patch
before them ("Applies on top of"). For 0001 to 0004 that is also a dependency in behaviour, since
all four rewrite the same ACK and timer code in `ngtcp2_conn.c`.

### Handshake and packet layout

Patches 0005, 0006, 0007, 0008, 0013, 0014, 0022 and 0027. 0007 moves the padding of the handshake
datagram to the leading Initial, and 0008 then sizes it to the discovered path MTU; 0008 also
corrects an assertion 0007 introduced. 0014 turns off 0005's SNI layout, 0006's packet-number rule
and 0007's deferred Initial while the parrot is on, and puts Chrome's in their place. 0022 moves
padding to right after the ACK, and 0027 does the same for an Initial CONNECTION_CLOSE.

### Congestion control and pacing

Patches 0009, 0010, 0011 and 0018. The last three need 0009: 0010 exists because 0009 took pacing
out of ngtcp2, 0011 gives 0009's controller arrival times, and 0018 adds the NewReno mode to
`ngtcp2_hybbr`. 0014 needs 0009 as well: it seeds the controller with the parrot's 1250-byte
packet size.

### Loss recovery and retransmission

Patches 0017, 0019, 0020, 0021, 0023, 0030, 0031 and 0032. 0019 and 0020 need 0018: 0019 changes
what hybbr is told about losses, and 0020 keeps NewReno running across a Retry. 0023 relies on
0022's rule that a STREAM frame without a Length field goes last. 0031 generalises the list of
ACK-only packets that 0030 kept for ECN, and uses 0028's handshake confirmation. 0032 follows on
from 0031's history model, and the packet number it skips on a PTO sits beside 0021's schedule.

### Flow control and streams

Patches 0012, 0016, 0024 and 0025. They are independent of each other in behaviour.

### Connection management and errors

Patches 0015, 0026 and 0033. 0033 reads every range of a received ACK because 0029 sends up to 64,
and its CRYPTO checks extend 0012's 16 KiB bound. It does not depend on 0027. Both concern
CONNECTION_CLOSE, but 0027 decides how the close is packed and 0033 what it says.

### Multi-core receive

Patch 0034. It comes after 0033 only because its hunks sit next to 0033's in the source; in
behaviour it depends on nothing else in the series.

## Tests

`make check` builds and runs every unit test in the tree, three of which exercise these patches.
All of them compile against the patched copy in `build/ngtcp2`, so a patch that stops applying
fails them first.

`tools/qgovec` produces `build/gen/qgo_vectors.h`. Its `gen.sh` lays small Go generators into the
vendored quic-go packages with `go test -overlay` and runs them there, so the vectors are what
quic-go's own code computes for the same inputs. Nothing under `vendor/` is written. It needs Go.

`test/ngpatch` drives ngtcp2's own client with null crypto, using the harness from ngtcp2's
`tests/`, and compares what it does with those vectors, one section per rule. It includes
`ngtcp2_conn.c` as source so that the static functions the patches add are in reach. It covers
0006, 0013 to 0017, 0019 to 0023, and 0025 to 0033. The 0030 section also exercises 0010's ACK
writer, and 0012's 16 KiB bound is checked among 0033's CRYPTO cases.

`test/hybbr` checks 0009's controller piece by piece: the bandwidth arithmetic, the windowed
filter, the sampler's containers, and the state machine driven from STARTUP into PROBE_BW. It also
steps 0018's NewReno mode through vectors from quic-go's `cubic_sender.go`.

`test/rxopen` checks that packets opened ahead with 0034's keys give ngtcp2 exactly what its own
callbacks would have produced, including after a key change and when an input does not match.

`make check-qgo-reasons` (`tools/qgoreasons`, part of `make check-builds`) holds every
CONNECTION_CLOSE reason that 0033 records to the literal text in `vendor/quic-go`.

To run one test: `make build/test-ngpatch && ./build/test-ngpatch`, and likewise for `hybbr` and
`rxopen`.

0001 to 0005, 0007, 0008, 0011 and 0024 have no dedicated unit test. They change timing and
datagram shape, which the unit tests do not model, and they were checked against the reference on
two stands in this tree instead. `tools/vendorcap/qstand` runs a quic-go server that records both
clients in its own qlog. `test/hystand` runs the hysteria server built from `vendor/`, and its
`loss.sh` puts an impaired path between that server and each client. Most of the measurements
quoted in the patch headers come from these two stands. Neither runs in `make check`.

## License

ngtcp2 is distributed under the MIT license, Copyright (c) 2016 ngtcp2 contributors (see `COPYING`
in the ngtcp2 tree). These patches are modifications of ngtcp2 and are distributed under the same
MIT license, including the files they add (`lib/ngtcp2_hybbr.c` and `lib/ngtcp2_hybbr.h`). The rest
of this client is licensed under MPL-2.0 (`LICENSE` at the repository root); that license does not
apply to the patches.

Most patches reimplement logic from quic-go (MIT, Copyright (c) 2016 the quic-go authors &
Google, Inc.). Two are close ports: 0009 of hysteria's BBR and pacer, which
hysteria in turn ported from Chromium (hysteria is MIT, see its `LICENSE.md`), and 0018 of
quic-go's NewReno sender and pacer. Anyone redistributing the patched library should keep those
notices alongside ngtcp2's.
