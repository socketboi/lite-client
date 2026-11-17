# lite-client

[![CI](https://github.com/socketboi/lite-client/actions/workflows/ci.yml/badge.svg)](https://github.com/socketboi/lite-client/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

A small **C client for OpenWrt routers**: VLESS / REALITY / XTLS-Vision, with an
optional Hysteria 2 plane. Intended for devices where larger proxy engines do
not fit comfortably, including the Xiaomi Mi Router 4A Gigabit.

You supply your own compatible server and credentials. This project supplies the
client, an OpenWrt service and package recipes. Traffic selection belongs to the
firewall; there is no server implementation or sing-box JSON configuration engine.

## Protocols and scope

| Area | Support |
| --- | --- |
| REALITY | VLESS over raw TCP, XTLS-Vision, XUDP over Mux.Cool |
| Hysteria 2 | QUIC / HTTP/3, UDP relay, Salamander and Gecko, port hopping, Brutal when a receive rate is set |
| References | Xray-core v26.11.9 and Hysteria app/v2.13.0, with exact dependency revisions pinned |
| Concurrency | REALITY defaults to one worker process per CPU; Hysteria uses one worker |
| Integration | OpenWrt procd, UCI and nftables TPROXY; credentials read from owner-only files |
| Configuration | UCI and command-line tools; one outbound per running instance |

The implementation targets the observable behavior of its pinned references.
Known differences and qualification limits are recorded in
[DIVERGENCES.md](DIVERGENCES.md),
[REALITY compatibility](docs/XRAY-COMPATIBILITY.md) and
[Hysteria compatibility](docs/HYSTERIA-COMPATIBILITY.md). These checks are not
an independent security audit or a guarantee against traffic identification.

## Read this before installing

The **bundled OpenWrt service** intercepts TCP ports **80 and 443**, and UDP port
**443** when its UDP listener is enabled, for the IPv4 clients you select.
The shipped profile enables separate TCP and UDP listeners.

- Other ports, DNS and IPv6 are not automatically carried by this profile.
- An empty client list selects nobody by address. External firewall integration
  is documented in [CONFIG.md](docs/CONFIG.md#external-marking-empty-clients).
- While the service runs, intercepted traffic goes through the tunnel or fails:
  a crashed worker does not cause those rules to disappear.
- **Stopping or disabling the service removes its interception rules.** This
  profile is not a whole-device Kill Switch.

For complete LAN coverage, routing policy and leak prevention, use an appropriate
firewall integration. The engine's TCP/UDP capabilities and the bundled profile's
traffic selection are separate concerns.

## OpenWrt support

| Firmware | Architecture / target | Qualification |
| --- | --- | --- |
| 25.12.5 | `mipsel_24kc`, `ramips/mt7621` | SDK / APK checks and Mi Router 4A Gigabit hardware coverage |
| 25.12.5 | `aarch64_cortex-a53`, `mediatek/filogic` | SDK / APK checks and AX3000T hardware coverage |
| 24.10.8 | `mipsel_24kc`, `ramips/mt7621` | SDK / IPK payload and QEMU checks; see the limits in [BUILD.md](docs/BUILD.md) |

Check the exact firmware, architecture and package dependencies before installing.
A different Mi Router 4A variant is not covered merely because its name is similar.
Other targets require their own build and qualification.

Recorded stripped executable sizes are about **0.79–0.92 MB** for REALITY and
**1.12–1.45 MB** with Hysteria. Package files, libraries and kernel modules need
additional flash. These are historical build observations, not current package
size promises. Memory and throughput depend on workload and hardware; see
[TESTING.md](docs/TESTING.md) for measured ranges and methodology.

## Install and configure

This is the initial public source release. Build an APK/IPK with the matching
OpenWrt SDK using [BUILD.md](docs/BUILD.md#the-openwrt-package).
GitHub Actions cross-build artifacts are executables for testing, **not installable
OpenWrt packages**. Availability of future prebuilt packages will be shown on the
[release page](https://github.com/socketboi/lite-client/releases).

Pick one package:

- `lite-client`: REALITY only.
- `lite-client-hysteria`: REALITY and Hysteria 2; replaces the base package.

[INSTALL.md](docs/INSTALL.md) covers package installation, verification, logs,
upgrades and removal. Unsigned local APK builds require explicit trust handling;
there is no public signing key to install yet.

For REALITY, after installing the package, run as root on the router:

```sh
umask 077
printf '%s\n' 'your-vless-uuid' > /etc/lite-client/uuid

uci set lite-client.main.node='server.example.com'
uci set lite-client.main.port='443'
uci set lite-client.main.sni='www.example.com'
uci set lite-client.main.public_key='server-public-key'
uci set lite-client.main.short_id='0123abcd'
uci add_list lite-client.main.clients='192.168.1.0/24'
uci set lite-client.main.enabled='1'
uci commit lite-client
/etc/init.d/lite-client enable
/etc/init.d/lite-client restart

logread | grep -E 'lite-client|lc-tunnel'
```

Replace the example values with your server's configuration. `sni` must be one
of its REALITY server names. The UUID file is private; do not attach it to issues.
For Hysteria, use the Hysteria-enabled package and the
[Hysteria configuration example](docs/CONFIG.md).

## Build and test from a fresh clone

Use a Linux x86-64 host with Git, Docker and enough disk space for the reference
sources, build image and toolchains. Windows / WSL details are in [BUILD.md](docs/BUILD.md).

```sh
git clone https://github.com/socketboi/lite-client.git
cd lite-client
sh tools/vendor/fetch.sh
docker build -t lc-build:local -f docker/Dockerfile .
docker run --rm -v "$PWD:/w" -w /w lc-build:local make tc-fetch
docker run --rm --network none -v "$PWD:/w" -w /w lc-build:local sh .github/scripts/link-stubs.sh
docker run --rm --network none -v "$PWD:/w" -w /w lc-build:local make check-spider-behavior
```

Fetching dependencies and building the image need internet access. The main
correctness gate then runs offline, including the MIPS and AArch64 cross-builds.
Live protocol stands, kernel/network tests and package qualification have their
own prerequisites and documented commands.

## Documentation and contributions

| Document | Start here for |
| --- | --- |
| [INSTALL.md](docs/INSTALL.md) | Install, inspect, upgrade and remove the package |
| [CONFIG.md](docs/CONFIG.md) | UCI options, secrets, server settings and firewall integration |
| [BUILD.md](docs/BUILD.md) | Dependencies, toolchains, package recipes and pinned revisions |
| [DESIGN.md](docs/DESIGN.md) | Architecture and known limitations |
| [TESTING.md](docs/TESTING.md) | Correctness gates and qualified performance observations |
| [DIVERGENCES.md](DIVERGENCES.md) | Deliberate differences from upstream behavior |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Changes, tests, source citations and sign-off |
| [SECURITY.md](SECURITY.md) | Private vulnerability reporting |

Questions belong in [Discussions](https://github.com/socketboi/lite-client/discussions).
Reproducible bugs belong in [Issues](https://github.com/socketboi/lite-client/issues).
Remove credentials, server addresses and personal data before posting logs.
Optional financial support is described in [SUPPORT.md](docs/SUPPORT.md).

## License and upstream work

[MPL-2.0](LICENSE). This is an independent implementation, including translations
of upstream code; it is not a fork of sing-box. Original authors, licenses and
required notices are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
