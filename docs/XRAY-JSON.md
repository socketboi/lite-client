# Run a complete Xray configuration

Xray mode uses the official Xray Core 26.11.9 build at commit `676eaf6`. It
executes Xray JSON and JSONC with the upstream configuration loader and
protocol implementations. Configurations are for a trusted administrator.
The JSON controls the listeners, outbound connections, routes, DNS and logs.

## Check and run on Linux

With a verified copy of the pinned Xray executable:

```sh
sh package-xray/lc-xray --core /absolute/path/to/xray check client.json
sh package-xray/lc-xray --core /absolute/path/to/xray run client.json
```

Supply several files in their merge order, or use `--confdir DIRECTORY`.
Files in that directory are sorted by name and loaded after any explicit
files. Xray reports its own validation errors. Keep the output private if it
contains configuration data. Stop a foreground run with Ctrl+C.

## OpenWrt

The `lite-client-xray` package installs the pinned executable and a separate
`procd` service. Select `lite-client-xray` as a package in the AArch64 SDK
configuration and compile its recipe from the SDK directory:

```sh
ln -s /absolute/path/to/lite-client/package-xray package/lite-client-xray
make menuconfig
make package/lite-client-xray/compile
```

Install the resulting package with the matching package manager. An OpenWrt
25.12 build produces `lite-client-xray-26.11.9-r1.apk`. The installed package
contains about 31.5 MiB of files before filesystem compression.

Select the optional `lite-client-xray-geodata` package in the SDK if the
profile uses `geoip.dat` or `geosite.dat`. It adds about 10.2 MiB of files.
The service looks for these files in `/usr/share/lite-client-xray`. Supply any
other files referenced by the profile at the paths it specifies.

Copy the JSON files into the private directory `/etc/lite-client-xray`.
Then validate and start:

```sh
/etc/init.d/lite-client-xray check
uci set lite-client-xray.main.enabled='1'
uci commit lite-client-xray
/etc/init.d/lite-client-xray enable
/etc/init.d/lite-client-xray start
/etc/init.d/lite-client-xray status
```

For a configuration update use `/etc/init.d/lite-client-xray reload`. A
failed preflight leaves the running instance registered with `procd`.
An upstream preflight checks configuration, while startup also needs
available listening ports and any devices or kernel features used by the
profile. TUN, for example, needs a working `/dev/net/tun` on OpenWrt.

Tunnel, HTTP, Shadowsocks, SOCKS, Trojan, VLESS, VMess, WireGuard, Hysteria,
MASQUE and TUN are the upstream inbound protocols in this pinned release.
The service does not install traffic interception rules. Any route or
interface changes requested by the JSON are performed by Xray itself.
Check available flash before installing the executable and any data packages.

## Verification

```sh
sh package-xray/check-runtime.sh
```

Run on x86-64 Linux with curl, Python 3 and OpenSSL. The script verifies the
release archive's SHA-256 before running Xray. The suite validates each inbound
and exercises multiple config files, listeners and outbound routes with local
traffic.
