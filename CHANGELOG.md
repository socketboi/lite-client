# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
change the UCI configuration or the command lines of the tools.

Each release names the reference revisions it was checked against. A difference from them that
is known at release time is listed in [DIVERGENCES.md](DIVERGENCES.md), not here.

## [0.1.0] - Unreleased

The first public release. How the client got here, including what was tried and dropped, is in
[docs/HISTORY.md](docs/HISTORY.md).

### Added

- The stock UCI profile assigns separate TCP and UDP listener ports, so native
  first-install validation accepts it without manual edits. The profile is
  checked with real OpenWrt UCI on MIPS and AArch64.
- Managed router upgrades explicitly migrate an empty historical UDP listener
  after authenticated package activation. Preparation uses a private UCI name
  to isolate live pending changes; owner ports and credentials are retained.

- Package release r4 declares the full variant as an IPK replacement of the
  REALITY-only package. APK qualification covers one solver transaction that
  promotes the base package to the full variant while preserving configuration
  and credentials.

- Bounded, opt-in supervisor crash evidence for the existing router diagnostic
  outbox. Worker exits retain their signal, source version and UUID across a
  successful replacement. This local evidence does not change protocol bytes.
- SDK release qualification for both variants on OpenWrt 24.10.8 MIPS/IPK and
  25.12.5 MIPS/APK and AArch64/APK. Package release r3 accepts a positive
  `LC_PACKAGE_BUILD` suffix so separate pipeline builds never reuse a version.

- Xray v26.11.9 behavioral references with its exact uTLS and REALITY revisions.
  TLS 1.3 ML-DSA CertificateVerify follows Go 1.27, including corrupted, wrong-key
  and parameter-name controls; Hysteria retains its pinned signature policy.
  Fragmented TLS reads follow uTLS's AvailableBuffer loop, checked against Go
  on amd64 and 386. Existing throughput reports keep their original versions.

- A local LAN/NAT qualification gate with ordered TCP/TLS and UDP receipts for
  selected, deselected and firewall-reloaded clients on both planes. Frozen
  inputs include the installed service script and the reference peer fixtures.
- Hysteria app/v2.13.0 qualification with its explicitly accepted trust_anchors
  fingerprint, an independent quic-go hello oracle, supporting-declaration
  mutation checks and loopback TCP/TLS/UDP mixed-load receipts.
- SHA256-pinned Filogic SDK fetching and APK install/upgrade qualification for
  AArch64 as well as MIPS, with the actual packaged binary executed under qemu.

- An offline two-boot OpenWrt service VM gate for real APK hooks, procd recovery,
  TCP/TLS/UDP through REALITY, and sysupgrade configuration backup/restore.
- A pinned, offline QEMU/OpenWrt guest gate for successful socket/TPROXY rule
  installation, repeated startup, cleanup and atomic nft failure rollback.
- Separate isolated real-kernel gates for rule rollback and successful TPROXY
  installation, with explicit unsupported-kernel results and retained receipts.
- `make check-package` qualifies actual SDK APK installation and fixture-version
  upgrades in disposable roots, including configuration/credential preservation,
  SDK-generated keep lists and packaged MIPS executables under qemu.
- `lc-tunnel`, a transparent proxy client for OpenWrt: TCP and UDP from the LAN through nftables
  tproxy, one outbound, plus direct and block. Traffic selection stays in nftables and dnsmasq;
  there is no routing engine and no JSON config.
- The REALITY plane: VLESS with XTLS-Vision over REALITY on raw TCP, as Xray-core v26.11.9 sends
  it. UDP travels as xudp over Mux.Cool, one stream per LAN client. The ClientHello is built from
  a fingerprint table generated from uTLS at the revision Xray-core pins (Firefox by default),
  with X25519MLKEM768 from mlkem-native and all three certificate compression algorithms (zlib,
  brotli, zstd) that the hello offers. When the node does not authenticate the client, the
  certificate chain and name are verified and the fallback fetch (the spider) behaves like
  Xray's, down to Go 1.27's HTTP/2 client.
- Reference upgrade qualification: generated Xray Vision close observations, Go 1.27.3
  SETTINGS/WINDOW_UPDATE comparisons and independent HTTP/2 header/trailer budget checks.
  Vision Direct suppresses the outer close notification only after raw copy begins.
- The Hysteria2 plane: QUIC on ngtcp2 and nghttp3 with a crypto backend written here instead of
  OpenSSL, HTTP/3 authentication, relayed datagrams, Brutal when a receive rate is set, Salamander
  and Gecko obfuscation, port hopping, certificate pinning, and Chrome's QUIC stack parroted by
  default as hysteria app/v2.13.0 does, including its trust_anchors extension. 34 patches in `patches/ngtcp2/` make ngtcp2 behave like
  the hysteria fork of quic-go, each citing the lines it follows.
- Multi-core operation where it does not change the wire: one REALITY process per core (up to
  eight), and decryption of incoming records and datagrams spread over the other cores on both
  planes. These are recorded as the maintainer's decisions in DIVERGENCES.md.
- Seven single-purpose tools beside the tunnel for checking one layer at a time: `lc-hello`,
  `lc-probe`, `lc-fetch`, `lc-xfetch` (the XHTTP transport, not yet used by the tunnel), `lc-hy`,
  `lc-hyfetch` and `lc-hydns`. All eight share one set of exit codes.
- An OpenWrt package in two variants, `lite-client` (REALITY only) and `lite-client-hysteria`
  (both planes), with a UCI configuration, a procd service, the firewall rules, TCP memory sizing
  for the router, and secrets kept in root-only files under `/etc/lite-client`.
- Cross builds for mipsel (MT7621) and aarch64 (MediaTek Filogic) with the OpenWrt 25.12.5
  toolchains, fetched and checked against pinned checksums (`make tc-fetch`).
- The gate, `make check`, in a build image defined by `docker/Dockerfile`: one suite per module,
  many of them fed by vectors that Go programs under `tools/` take from the reference code itself;
  checks that every citation of the reference points at a real file and line, that the registry
  of divergences matches the `DIVERGES:` marks in the code, that the shipped fingerprint tables
  are what uTLS produces today and that every vendored tree sits at its pinned revision; builds
  for both routers in both configurations; and the arm64 AES-GCM and ChaCha20 paths run under
  qemu. The required `make check-spider-behavior` target adds the controlled Go/C
  spider-close oracle. Checkpoint analyzer tests run within `make check`;
  [spider acceptance](docs/SPIDER-ACCEPTANCE.md) records the current checkpoint
  formats and diagnostic scheduler metrics.
- Executable host/native spider checkpoint drivers with frozen inputs, owned
  listener checks, signal cleanup and native memory/process/configuration
  evidence validation, including mandatory resource-monitor termination checks.
- `DIVERGENCES.md`, the one list of where this client is known to differ from its reference.
- A live Hysteria2 stand (`test/hystand/run.sh`) that runs the reference server from `vendor/`
  and pushes traffic through this client.

### Fixed

- Package revision `r2` preserves foreign packet-mark bits and reserves only
  `0x1000000/0x1000000`, with RPDB priority 102 before mwan3 member rules.
  Upgrade cleanup retires the historical `0x40404` rules for tables 101 and 104.
  Selected packets are marked before TPROXY, including when its listener is absent.
- Native lab teardown discovers child processes through PPid on OpenWrt kernels
  without task/children; procd PID observations reject transitional null values.
- Native policy qualification stops on new kernel OOM evidence or a terminated
  resource observer, including when procd restarts the process killed by OOM.
  Concurrent observations use isolated snapshots rather than shared scratch files.
- Native mixed-load stands write HTTP/UDP receipts before acknowledging traffic
  and stop on a receipt write failure. Full-disk tests use `/dev/full` in an
  isolated build environment instead of filling shared storage.
- Native qualification verifies the executing driver and installed service,
  serializes lab drivers, detects terminated workloads and restores the declared
  selection before final snapshots. Functional observer budgets are recorded
  explicitly instead of interpreting a five-second expiry as datagram loss.
- UDP interception uses explicit selected-client rules. A generic transparent
  socket divert could capture deselected traffic in send-only reply sockets,
  preventing its return to the direct path after an earlier proxied request.
- AArch64 hardware crypto adds the crypto extension without resetting the SDK's
  CPU features, preserving calls to OpenWrt's fortified inline string wrappers.
- Readiness requires a socket registered in its live owner's epoll loop. A
  supervisor retaining the shared TCP listener, or a stopped worker, cannot
  report ready while no consumer is serving it.
- Fingerprint/public file reads reject FIFOs, devices and directories without
  reading them. Read errors reject even a complete valid prefix; regular-file
  symlinks and exact-size/empty-file boundaries remain supported.
- Service startup reports rejected configuration and unready listeners with
  status 1. Listener ownership includes direct workers via portable proc status;
  foreign listeners do not report success. Readiness failure retains interception
  and procd retries rather than allowing a direct traffic bypass.
- procd hashes the executable and fingerprint table as managed startup inputs.
  APK upgrades with unchanged UCI/argv can no longer retain the old process image.
- Repeated starts with disabled or rejected configuration remove old interception
  before rc.common drops the previous process. Invalid client lists are refused
  before TCP tuning/procd preparation; trailing-dot IPv4 clients are rejected.
- Firewall startup errors no longer infer tunnel liveness from an unrelated
  process name before rc.common publishes the prepared service.
- The service validates its complete command with `lc-tunnel --check-config`
  before TCP tuning, procd registration or interception. Invalid credential
  files and fingerprint tables cannot reach those startup effects.
- Secret-file validation rejects FIFOs without blocking on opening them.
- Empty TLS record protection avoids zero-length copies through a null plaintext
  pointer in TLS 1.3 and all TLS 1.2 record modes. Existing payload bytes and
  record sequence semantics are preserved.

### Reference revisions

- REALITY plane: Xray-core v26.10.31 and XTLS REALITY `83f6217`. The fingerprint tables come from
  the uTLS Xray-core pins (`aa6edf4b11af`); code citations point into uTLS `23b1dac`, a later commit
  whose ClientHello code is byte-identical (see "Pinned revisions" in
  [docs/BUILD.md](docs/BUILD.md#pinned-revisions)).
- Hysteria2 plane: hysteria app/v2.13.0 and its quic-go fork `a10df75c`, with Go 1.26 reference generators.
- Linked from the router: mbedTLS 3.6.6 and zlib (only their headers are in the build).
  Compiled in: mlkem-native, the brotli 1.1.0 and zstd 1.5.7 decoders, ngtcp2 and nghttp3.

### Known limitations

- On the Hysteria2 plane the node's name is resolved once at start, as the hysteria client does.
- There is no graceful shutdown: SIGTERM stops the process where it stands.
- XTLS-Vision works only on raw TCP, as upstream requires.

[0.1.0]: https://github.com/socketboi/lite-client/commits/main
