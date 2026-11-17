# Unbihex implementation review

Reviewed on 2026-10-30 at
[`c3a335f730be4a1c9d9fb5b671a59cb5212caafb`](https://github.com/crystalmasta/unbihex/commit/c3a335f730be4a1c9d9fb5b671a59cb5212caafb),
following the owner's [article](https://habr.com/ru/articles/1100854/).
The inspected engine manifest declares version 0.1.3. This is source review;
no Rust executable was built or measured on a router. The article's memory
figures are not matched OpenWrt RAM, flash or throughput measurements.

Xray/uTLS and hysteria remain the protocol references. Unbihex supplies questions
to investigate, not acceptance criteria. Its implementation choices require
independent verification against the pinned references before use in LiteClient.

## Mechanisms to verify against the pinned references

- [`relay.rs::copy_one/relay_tcp`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/relay.rs)
  runs independent directions, flushes accepted bytes and propagates half-close.
  Its copy buffer starts at 16 KiB per direction and grows to 64 KiB after a full
  read. This is a useful allocation strategy to investigate, with LiteClient's
  existing record sizes, backpressure and reference behavior held fixed.
- [`VisionStream::poll_first_packet`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/outbound/vision.rs)
  continues reads when an initial write is pending. The relevant invariant is
  that a full upload socket must not block an otherwise runnable download.
- [`Instance::reload`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/lib.rs)
  validates and builds new routing/outbounds before publishing a table through
  [`Dispatcher::swap_table`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/dispatcher.rs).
  Existing sessions retain their selected outbound. Inbounds, DNS and limits
  remain fixed; this is not unrestricted live configuration replacement.
- [`tun.rs::is_multicast_or_broadcast`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/inbound/tun.rs)
  rejects multicast and limited broadcast before UDP dispatch/connection slots.
  That addresses its TUN routing loop; LiteClient uses TPROXY, so adding the
  same filter would require checking the existing inbound/protocol contract.

## Behaviors that cannot replace the pinned reference

- `VisionStream::queue_padded` ends outgoing padding with CMD_END; it does not
  select CMD_DIRECT for uplink. It follows a peer's CMD_DIRECT for reads via
  [`TlsRecordStream::switch_to_raw_read/poll_read`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/outbound/tls_stream.rs).
  The inspected paths are not evidence of equivalent Linux splice behavior.
- [`Fingerprint::from_name`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/outbound/fingerprint.rs)
  maps names other than none/rustls to Chrome. A Firefox request therefore does
  not establish a Firefox fingerprint. LiteClient retains its exact pinned
  browser tables rather than adopting this name mapping.
- [`RealityVerifier::verify_server_cert`](https://github.com/crystalmasta/unbihex/blob/c3a335f730be4a1c9d9fb5b671a59cb5212caafb/unbihex-engine/src/outbound/reality.rs)
  rejects a certificate without the expected temporary-certificate HMAC proof.
  This is not the pinned Xray behavior for an ordinary valid masquerade-site
  certificate; removing LiteClient's certificate validation/browsing path would
  change observable protocol behavior.
- `relay_tcp` uses an idle-based half-close grace of at most ten seconds. Those
  timer semantics are not Xray's ActivityTimer/splice semantics and must not
  replace LiteClient's pinned timers merely because both clients connect.

No Unbihex code or dependency is imported into LiteClient by this review.
Subsequent implementation work must still use the pinned Xray/hysteria sources
to decide wire behavior, and matched hardware/path/configuration for performance
claims.

## Verified LiteClient follow-up: interrupted uplink I/O

The independent-direction question was checked against pinned Xray
`proxy/vless/outbound/outbound.go::postRequest/getResponse` and
`proxy/proxy.go::CopyRawConnIfExist`, not against the Rust relay's timers.
For syscall interruption, Go 1.27.1 `internal/poll/fd_unix.go::Read` and
`internal/poll/writev.go::Writev` retry EINTR. Xray's
`common/buf/readv_reader.go::readMulti` retains its allocation when its read
callback has no result; `common/buf/writer.go::WriteMultiBuffer` uses net.Buffers
for multiple raw buffers.

LiteClient's multi-buffer path could instead fail on interrupted metadata,
peek or drain reads, defer an interrupted empty-queue probe, or queue an
interrupted raw write as backpressure. It now retries EINTR at the interrupted
operation without repeating reader adaptation or framing. A zero-byte raw write
is rejected like Go Writev's initial zero-progress write. The deterministic
socket fixture and its validation scope are documented in TESTING.md.

## Verified LiteClient follow-up: buffered bytes before raw copy

Pinned Xray `proxy/proxy.go::VisionReader.ReadMultiBuffer` merges TLS input and
rawInput into one returned MultiBuffer. `proxy/vless/encoding/encoding.go::XtlsRead`
completes WriteMultiBuffer before its next iteration enters raw copy. This is the
authority for ordering; the Rust stream's implementation is not the oracle.

LiteClient could leave a tail unqueued after Flush emptied its queue, stranding
it without a future event or allowing newer raw bytes to pass it. The carry now
continues when the writer creates room; new raw reads wait for the older write.
The epoll watch follows reader ownership, including unconditional HUP and an
independent runnable uplink writer. TESTING.md records the socket/copy/splice
regressions and distinguishes component execution from source review and router
acceptance.

## Verified LiteClient follow-up: close_notify under backpressure

Pinned uTLS `conn.go::Conn.Close/closeNotify` allows five seconds for one alert
write; Xray `proxy/vless/outbound/outbound.go::Process` defers that Close.
LiteClient's previous one-shot nonblocking write could instead lose or truncate
the alert. Closing now retains the sealed record, session and both endpoints
across WRITE readiness until completion, error or the original deadline. Active
application writes still close immediately, matching uTLS's activeCall rule.
No Rust timer, protocol fallback or new close frame is adopted.

TESTING.md records the old-runtime failures, isolated mutations and native
component execution on the lab Mi Router 4A, including the preceding Vision
copy/splice/carry fixture. This does not establish full VPN or performance parity.

## Verified LiteClient follow-up: endpoint close order

Pinned Xray `proxy/vless/outbound/outbound.go::Handler.Process` defers the node
Close; `proxy/dokodemo/dokodemo.go::DokodemoDoor.Process` waits for DispatchLink
before returning, then `app/proxyman/inbound/worker.go::tcpWorker.callback` closes
the inbound connection. uTLS `conn.go::Conn.Close` closes the node transport even
when close_notify fails. LiteClient's final teardown closed LAN first. It now
finishes the node transport before releasing the client endpoint, including
backpressure, write failure and timeout paths. This specifies local close order;
packet arrival order across separate network paths is not guaranteed.

Six new close-order scenarios extend the previous twelve ownership checks,
including TLS 1.3/TLS 1.2 over local TCP. TESTING.md records their validation scope.

## Verified LiteClient follow-up: first read interrupted beside TCP reset

Pinned Xray `common/buf/readv_reader.go::ReadVReader.ReadMultiBuffer` calls
`common/buf/reader.go::ReadBuffer` for its first buffer. Go 1.27.1
`internal/poll/fd_unix.go::FD.Read` retries EINTR inside `ignoringEINTRIO`.
LiteClient's multi-buffer retry fixes did not cover that first-buffer branch:
an interruption alongside a socket error could close it with unread TCP data.

The first read now retries EINTR before interpreting readiness flags or adapting
and framing the buffer. Eight real TCP/epoll cases cover reset, half-close, EOF
and errors; the old read behavior fails and the fixed fixture passes on the
test 4A as well as host and MIPS32/AArch64 QEMU. TESTING.md records the baseline,
isolated mutations, sanitizer coverage and component-only validation scope.

## Verified LiteClient follow-up: full native tunnel integration

The current temporary MIPS client passed the four plain/TLS 1.3 combinations
of REALITY/Vision and Hysteria2 against pinned reference servers on the lab 4A.
The matrix includes checked duplex traffic, parallel flows, backpressure, UDP
boundaries, invalid credentials, server restart and Hysteria silent-peer timeout.
TESTING.md records 105 asserted checkpoints and the isolated stand's limits.
The apparent parallel stall was in the shared SSH load adapter; no client
protocol change was needed. This does not close G2, establish performance parity
or replace extended soak and AX3000T acceptance.
