# Installing lite-client on OpenWrt

## Which package

There are two packages built from the same source. Install one of them, not both: they carry the
same files.

| package | planes | when to use it |
|---|---|---|
| `lite-client` | REALITY | your server is Xray with VLESS + REALITY |
| `lite-client-hysteria` | REALITY and Hysteria2 | your server is Hysteria2, or you want both options |

The Hysteria2 build is nearly twice the size (1.32 MB against 725 KB on mipsel; see "Sizes" in
[BUILD.md](BUILD.md#sizes)), because it carries a QUIC stack. `lc-tunnel --planes` prints which
planes an installed binary has.

## Requirements

- OpenWrt with fw4 and nftables. The maintainer builds against 25.12 and runs it on `ramips/mt7621`
  (`mipsel_24kc`) and `mediatek/filogic` (`aarch64_cortex-a53`).
- A package built for your router's architecture. `apk --print-arch` (25.x) or
  `opkg print-architecture` (24.x) tells you which one that is.
- Enough free flash for the selected package and every missing dependency. Recorded
  executable sizes are roughly 0.79 to 1.45 MB; this is not the total installed size.

The package pulls in these dependencies, most of which a stock image already has:

| dependency | why |
|---|---|
| `libmbedtls` | AES, X25519, the arithmetic of the certificate checks. The binary links the system's libmbedcrypto. |
| `zlib` | certificate compression |
| `ca-bundle` | REALITY: verifying the masquerade site's certificate when the server does not recognise the client, as Xray does |
| `kmod-nft-tproxy`, `kmod-nft-socket` | the interception rules |
| `ip-full` | the policy routing rule for marked packets |

## Getting a package

The initial public source release does not publish prebuilt APK/IPK packages.
Build one with the matching OpenWrt SDK, as described in [BUILD.md](BUILD.md).
GitHub Actions cross-build artifacts contain test executables, not packages.
Future installable releases will be listed on the project's release page.

The qualified SDK matrix is 25.12.5 for MT7621/MIPS and Filogic/AArch64, plus
24.10.8 for MT7621/MIPS. Use the exact firmware and architecture for the package;
it links against the system's mbedTLS and musl. Other releases need their own
build and qualification. The model name alone is not an ABI check.

## Installing

OpenWrt 25.x uses apk:

```sh
apk update
apk add --allow-untrusted ./lite-client-0.1.0-r4.apk
```

Use the actual filename of the one package you built. Do not pass a wildcard
that also selects the conflicting Hysteria-enabled variant. `--allow-untrusted`
is for these unsigned local builds: there is no public release signing key yet.
It bypasses package signature verification; obtain the source from the official
repository and build it yourself.

OpenWrt 24.10 uses opkg and `.ipk` packages, which only an SDK of the 24.10 series produces:

```sh
opkg update            # so that dependencies can be fetched
opkg install ./lite-client_*.ipk
```

The 24.10.8 SDK/IPK checks inspect both payloads and execute their binaries under
QEMU. They do not by themselves establish successful opkg hooks or operation on
every 24.10 router; see the qualification limits in [BUILD.md](BUILD.md).

To switch variants, remove one and install the other. `/etc/config/lite-client` and the secret files
are kept.

```sh
apk del lite-client && apk add --allow-untrusted ./lite-client-hysteria-*.apk
```

## Enabling it

After installation the service is registered with procd but does nothing: the shipped configuration
has `enabled '0'` and no clients, so nothing is intercepted. Fill in the configuration
([CONFIG.md](CONFIG.md)), put the credentials in their files, then:

```sh
uci set lite-client.main.enabled='1'
uci commit lite-client
/etc/init.d/lite-client enable
/etc/init.d/lite-client restart
```

The service also restarts by itself whenever the WAN interface comes up, and `reload` is a full
stop and start, so a changed configuration never runs against the old rules.

## Checking that it runs

```sh
/etc/init.d/lite-client status        # "running"
ps | grep '[l]c-tunnel'               # the process (a parent and one worker per CPU on REALITY)
nft list table inet lite_client       # the intercept rules, with packet counters
ip rule show | grep 0x1000000        # the masked routing rule for selected packets
```

From a LAN host that is in `clients`, open any "what is my IP" page over HTTPS: it should show the
server's address. Remember that this profile intercepts TCP 80 and 443, plus UDP
443 with its configured UDP listener. The shipped profile sets `udp_port` to
19100. Removing or emptying that option lets QUIC go around the tunnel. DNS,
IPv6 and other ports retain their ordinary routes.

`lc-tunnel` prints a statistics block when it gets `SIGUSR1`. With several workers, send it to the
parent (the oldest process) and it is forwarded to each worker:

```sh
kill -USR1 "$(pgrep -o lc-tunnel)"
logread | tail -40
```

## Logs

Everything goes to syslog. Lines from the service script are tagged `lite-client`; lines from the
tunnel are tagged `lc-tunnel`, and with more than one worker they start with `[w0]`, `[w1]` and so on.

```sh
logread | grep -E 'lite-client|lc-tunnel'
logread -f | grep -E 'lite-client|lc-tunnel'     # follow
```

When the service refuses to start, it says why in one line before touching the firewall. Some of the
lines you may see:

| message | meaning |
|---|---|
| `disabled in the configuration; not starting` | `enabled` is 0 |
| `node and sni are required; not starting` | fill in `node` and `sni` |
| `cannot read /etc/lite-client/uuid; not starting` | the credential file is missing or unreadable |
| `this build has no 'hysteria' plane; not starting` | `plane` is `hysteria` but the REALITY-only package is installed |
| `pin is not set: the node would not be authenticated at all` | Hysteria2 needs `pin` (see CONFIG.md) |
| `udp_port is unset: UDP is not intercepted, so QUIC leaves this router directly` | informational |
| `IPv6 is not intercepted; only IPv4 ports 80 and 443 enter the tunnel` | informational, on every start |
| `tcp memory: ... pages (...), a socket up to ... bytes` | the TCP memory sizing the service applied (CONFIG.md) |
| `... is /some/path, which sysupgrade does not keep; see the conffiles` | a `*_file` option points outside `/etc/lite-client` |

If the tunnel itself cannot read a secret file, it names the reason: a symbolic link, not a regular
file, owned by another user, readable beyond its owner (`chmod 0600` it), empty, or with a zero byte
in it (a file saved as UTF-16).

`LC_OPEN_LOG` and the other diagnostic switches are described in [DESIGN.md](DESIGN.md). They are
off by default, and `LC_OPEN_LOG` in particular writes every destination to syslog.

## Firmware upgrades

A sysupgrade keeps `/etc/config/lite-client`, `/etc/lite-client/uuid`, `/etc/lite-client/auth` and
`/etc/lite-client/obfs`. It does not keep the package itself unless it is part of your image, so
reinstall the package after upgrading. If you point `uuid_file`, `auth_file` or `obfs_file` at
another path, that file is not preserved, and the service warns about it at every start.

## Removing it

```sh
/etc/init.d/lite-client stop       # takes the intercept rules down
/etc/init.d/lite-client disable
apk del lite-client                # or: opkg remove lite-client
rm -rf /etc/lite-client /etc/config/lite-client   # if you want the credentials gone too
```

The TCP memory settings the service raised stay in effect until the next reboot.
