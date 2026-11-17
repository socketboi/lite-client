# Hysteria2 interoperability — 6 November 2026

The client reference is Hysteria `app/v2.13.0`, commit
`ca8fbd874fd6ca82413948de6dc5924405e103e1`, and its apernet/quic-go dependency
`a10df75c260cee8161f3261d63a37bd125a6bb2a`.
The preceding pins were `e1366b173ccf5706e1e4630fe8aa654a4b574085`
(`app/v2.12.3`) and `73339f7edbb9be83b0f87b3c07390413138c6721`.

This remains a local, unreleased candidate. Package qualification, physical
device installation, firmware sysupgrade and native throughput are separate
checks. Historical native results retain their original executable hashes.

## Source comparison and the accepted fingerprint change

The reference diff leaves `core/client`, `core/internal/protocol` and
`extras/obfs` unchanged. This preserves the client authentication, TCP request,
UDP serialization/size limits, reconnect policy, Salamander and Gecko contracts.
The TUN changes are in `app/cmd/client.go::newTUNServer` and `app/internal/tun`.
Server sniffing now holds multiple UDP packets through
`core/server/udp.go::udpSessionEntry.Feed` and `RequestHook.UDP`; these are
server/application operations.

The QUIC diff contains an observable ClientHello change:
`internal/handshake/chrome_client_hello.go::chromeQUICClientHelloSpec` adds
`trust_anchors` (`0xca34`). Its length-prefixed anchor IDs are sorted by
`encodeTrustAnchorIDs`. The owner explicitly accepted this fingerprint change
on 6 November 2026. The REALITY fingerprint remains unchanged.

The compiled Hysteria table now carries twelve extensions. `tools/fp speccheck`
compares the spec function, extension ID, anchor list, data binding and encoder
against the pinned source. Isolated mutations of those supporting declarations
must fail. `tools/qgovec/trustanchors.sh` separately compiles an overlay test in
the actual quic-go handshake package, with its uTLS v1.8.2. The C hello suite
compares the resulting bytes with what `lc_qtls` writes, independently of the
fingerprint tool's copy. The existing table/rebuild/shuffle checks still run.

HelloRetryRequest tests derive the cookie insertion bound from the actual first
hello, matching uTLS's `Intn(len(Extensions)-2)` rule. They no longer assume the
previous eleven-extension profile.

`packet_packer.go::packetPacker.packConnectionClose` now includes the 1-RTT
AEAD overhead in the coalesced datagram's size. The existing ngtcp2 adaptation
already measures its sealed tail. The regression suite exercises both
Initial+Handshake and Initial+Handshake+1-RTT, including exact datagram size
and padding placement. HTTP/3 error wrapping and server-side `:path` validation
also changed upstream; the authentication request/QPACK client bytes remain
covered by their existing reference vectors.

The client standard-library oracles remain pinned to Go 1.26.6. The local
reference server is also built and identified with Go 1.27.3 for interoperability
with the deployed server toolchain. A server build does not change the selected
client oracle's standard-library version.

## Local qualification

Build the documented `docker/Dockerfile` after fetching the new pins, then run
`make check-spider-behavior` offline. It includes both plane configurations,
MIPS/AArch64 cross-builds, crypto execution under qemu, citation claims,
fingerprint oracles and controlled REALITY spider closure. The image explicitly
seeds quic-go's dependencies for the independent trust-anchor oracle.

`test/hystand/qualify.py` supplies a loopback-only live gate. It runs the actual
reference server and two temporary client processes, with four simultaneous
duplex connections per plain/TLS mode. Every one-MiB upload/echo has a checked
SHA256 backend receipt. UDP covers fragmentation, the header-inclusive 4096-byte
limit, silent oversize drop and a valid echo after that drop. Invalid password
and pin must exit before opening a listener. A deliberate backend-corruption
control must fail.

Run only inside the Linux build environment, with fresh output directories:

Prepare the identified reference server with network access before running the
workload offline. Disable the upstream workspace so preparation cannot rewrite
its `go.work.sum` in the read-only vendor checkout:

```sh
ref=$(git -C vendor/hysteria rev-parse HEAD)
(cd vendor/hysteria/app && GOWORK=off CGO_ENABLED=0 /usr/local/go1.27/bin/go build \
  -mod=readonly -trimpath -ldflags "-X github.com/apernet/hysteria/app/v2/cmd.appVersion=app/v2.13.0 \
  -X github.com/apernet/hysteria/app/v2/cmd.appCommit=$ref" -o /out/ref-hysteria .)
```

Then, with network disabled and the host client already built:

```sh
python3 test/hystand/qualify.py --client /out/lc-tunnel \
  --server /out/ref-hysteria --output /out/mixed-none --seconds 300
python3 test/hystand/qualify.py --client /out/lc-tunnel \
  --server /out/ref-hysteria --output /out/mixed-salamander --seconds 30 --obfs salamander
python3 test/hystand/qualify.py --client /out/lc-tunnel \
  --server /out/ref-hysteria --output /out/mixed-gecko --seconds 30 --obfs gecko
python3 /out/mixed-none/inputs/driver --analyze /out/mixed-none
```

Each output retains copied input executables/driver, hashes, backend receipts,
process exits, resource observations and logs. The standalone analyzer verifies
those identities, counts and receipts; failed or incomplete runs cannot pass.
Optimized Python is refused. Readiness checks socket ownership across IPv4 and
IPv6. Only owned process groups are terminated. RAM observations are diagnostic.
These bounded host workloads establish neither hardware throughput nor a native
long-soak result.

## Packages from a committed revision

Build both variants from one recorded Git revision, retaining each APK and its
qualification receipts. The MT7621 and Filogic SDKs are separately SHA256-pinned;
Host, package and qualification stamps use an explicit twelve-digit Git
abbreviation, independent of Git's default abbreviation heuristic.
`check-package` reads the SDK's configured package architecture and executes the
actual installed binary under qemu-mipsel or qemu-aarch64. It checks plane
support, configuration validation, special-file refusal and preservation of
owner-modified configuration/0600 credentials through a fixture-version upgrade.

The actual Filogic SDK also covers fortified string wrappers with its
`-mcpu=cortex-a53` flags. Hardware crypto uses `target("+crypto")` to preserve
those base CPU features; resetting them with `arch=armv8-a+crypto` can reject
always-inline `memcpy` calls. The existing AEAD suite runs with those SDK
headers and libraries under qemu and must select PMULL/NEON hardware paths.

Local test packages remain unsigned without creating signing keys. No package
is installed on a working router by these checks. Physical reboot, firmware
flashing and a long matched native workload on those exact package executables
remain the subsequent hardware qualification described in
[the release checklist](XRAY-COMPATIBILITY.md#local-package-candidate--6-november-2026).
