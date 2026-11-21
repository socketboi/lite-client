# Configuring lite-client

For a complete Xray JSON or JSONC profile, see [Xray Core mode](XRAY-JSON.md).
The settings below configure the native client.

The configuration is one UCI section, `lite-client.main`, in `/etc/config/lite-client`. The service
script `/etc/init.d/lite-client` reads it, checks every value, and only then starts `lc-tunnel` and
installs the firewall rules. A value it cannot use stops the start with a line in syslog; nothing is
intercepted in that case.

Before tuning TCP, publishing the procd command or installing rules, the script
also runs the client's parser with `--check-config`. It checks the actual
credential ownership, permissions, file type/content and fingerprint format.
This mode opens no listeners, forks no workers and does not resolve or contact
the node; it validates configuration rather than network availability.

Each start first removes LiteClient's previous interception. OpenWrt's
`rc.common` publishes an empty service when a repeated start is disabled or
rejected, stopping the old instance. Early cleanup prevents old rules from
directing traffic into that stopped process. Invalid client addresses/prefixes
are refused before TCP tuning or preparing a new procd instance.

The init script and binary must be updated together. The package ships both.

After publishing the instance, `start` checks that its TCP listener and configured
UDP listener belong to that procd PID or its direct workers running the current
executable. A foreign process holding the ports does not count as readiness.
The socket must be registered in that owner's epoll loop, and a stopped or dead
owner does not count. The supervisor's retained shared TCP socket alone is
insufficient while every worker is restarting.
The check makes ten attempts with one-second pauses and a one-second ubus timeout.
Failure returns status 1 while keeping interception and procd retries in place;
it does not establish upstream reachability. Disabled configuration returns 0;
rejected configuration returns 1. procd watches the executable and fingerprint
table as well as UCI, so APK upgrades replace a running old image even when the
command line is unchanged.
A new init script paired with an older binary that lacks `--check-config`
refuses to start before changing system state. There is no validation bypass.

Credentials are not in this file. They live in files of their own under `/etc/lite-client`, see
"Secret files" below.

## Options

UCI treats an option set to the empty string the same as an option that is not set, so for options
with a default, `''` means the default.

### Both planes

| option | default | meaning |
|---|---|---|
| `enabled` | `0` | `1` to run. Anything that is not a yes or no word is refused with a log line. |
| `plane` | `reality` | `reality` or `hysteria`. The REALITY-only package refuses `hysteria`. |
| `node` | (required) | The server, as an IPv4 or IPv6 address or a host name. |
| `port` | `443` | The server's port. On the Hysteria2 plane it may be a range, `20000-50000`, for port hopping. |
| `sni` | (required) | The server name the handshake claims. REALITY: one of the server's `serverNames`. Hysteria2: the name in the server's certificate. |
| `listen_port` | `19099` | Where the transparent TCP listener waits. Nothing connects to it directly; the firewall rules send traffic to it. |
| `udp_port` | `19100` in the shipped profile | A second listener for UDP, plus interception of UDP 443 (QUIC). Removing or emptying this option disables UDP interception; QUIC then goes directly. Must differ from `listen_port`. |
| `workers` | (unset) | How many copies of the tunnel share the listeners: `1` to `8`, or `auto` for one per CPU. Unset leaves it to the client: one per CPU on REALITY, one on Hysteria2. On the Hysteria2 plane only `1` is accepted. |
| `clients` | (empty) | Whose traffic is intercepted: IPv4 addresses or prefixes, as a list. Empty means nobody by address; see "External marking" below. An IPv6 entry is refused. |

`workers` splits connections between cores. A single download stays in one worker and is exactly as
fast as it would be with one. A household with many connections at once is what gains.

Multiple REALITY workers require a shared spider path cache. If it cannot be
initialized, `lc-tunnel` logs `cannot initialize shared spider paths` and exits
with status 1 before opening listeners or starting workers. It does not run with
separate path caches. The configured procd respawn policy retries startup.

If one worker cannot be forked, healthy workers keep serving while the missing
slot is retried after five seconds. A worker that crashes shortly after starting
also gets that pause; diagnostic requests remain available during it. If every
fork fails, the supervisor exits so procd can restart the service.

Before opening listeners, the tunnel restores the default SIGTERM action and
unblocks SIGTERM, including when its launcher ignored or blocked it before exec.
Stopping the supervisor also terminates its workers through the existing kernel
parent-death signal. Signal setup errors stop startup with status 1 and a diagnostic.

### REALITY

| option | default | meaning |
|---|---|---|
| `public_key` | (required) | The server's X25519 public key, hex or base64url, as Xray prints it. |
| `short_id` | (empty) | One of the server's `shortIds`, in hex, up to 16 characters and an even number of them. Empty is valid when the server lists `""`. |
| `uuid_file` | `/etc/lite-client/uuid` | File whose first line is the VLESS user id. |
| `flow` | `xtls-rprx-vision` | `xtls-rprx-vision`, `xtls-rprx-vision-udp443` (Vision with Xray's `allowUDP443`), or `none` for plain VLESS without Vision. Anything else is refused. |

Without Vision a second TLS runs inside the tunnel, and the record sizes give it away. Use `none`
only when the server's user has no flow. Note that `flow ''` gives the default, Vision; write `none`
to turn it off.

The ClientHello fingerprint is Firefox's, from `/etc/lite-client/fingerprint.fpt`, which the package
installs. There is no option for it.

### Hysteria2

| option | default | meaning |
|---|---|---|
| `auth_file` | `/etc/lite-client/auth` | File whose first line is the account password (hysteria's `auth`). |
| `auth` | (unset) | The same, written out. Wins over `auth_file`. For a quick test only: procd keeps the command line, and so the password, visible in `ubus call service list` while the service runs. |
| `obfs_file` | `/etc/lite-client/obfs` | File whose first line is the obfuscation password (Salamander, or Gecko with `gecko`). If you did not change this option and the file does not exist, the client runs without obfuscation. If you set a path, or the default file exists, it must be readable or the service does not start. |
| `obfs` | (unset) | The obfuscation password written out. Wins over `obfs_file`, with the same caveat as `auth`. |
| `pin` | (required) | SHA-256 of the server's certificate in DER, 64 hex characters, no colons. Get it on the server with `openssl x509 -in cert.pem -outform der \| sha256sum`. `-` runs without authenticating the server, and the log says so. |
| `rate` | (unset) | The rate you can receive at, in **bytes** per second. The server then sends at that rate with Brutal, whatever the path is doing. hysteria's `bandwidth.down: 100 mbps` is `12500000`. Unset means ordinary congestion control. |
| `hop_seconds` | (unset) | Seconds between port hops, at least 5. Only used when `port` is a range; with a single port nothing hops, and the tunnel logs that. With a range and no `hop_seconds`, the client hops every 30 seconds, as hysteria does. |
| `gecko` | (unset) | Gecko obfuscation, as the server's packet sizes `MIN-MAX` (hysteria's defaults are `512-1200`). Set it if and only if the server runs Gecko: a Gecko server drops everything else, and a server without it drops Gecko frames. Either mismatch looks like a server that never answers. |
| `chrome_parrot` | on | Parrot Chrome's QUIC stack, as the hysteria 2.11+ client does by default. `0`, `off`, `no` or `false` turns it off, which is hysteria's `quic.disableChromeParrot: true`. The server accepts either. |

Obfuscation has to match the server exactly. A wrong or missing Salamander password looks the same
as a server that is down.

Options that belong to the other plane are ignored with a log line: `pin`, `rate`, `hop_seconds`,
`gecko` and `chrome_parrot` do nothing on the REALITY plane.

## Secret files

| file | used by | content |
|---|---|---|
| `/etc/lite-client/uuid` | REALITY | the VLESS id, one line |
| `/etc/lite-client/auth` | Hysteria2 | the password, one line |
| `/etc/lite-client/obfs` | Hysteria2 | the Salamander or Gecko password, one line |

The directory is created by the package with mode 0700. Each file must be a regular file (not a
symbolic link) owned by root with mode 0600. `lc-tunnel` checks this and refuses anything else, so
create them like this:

```sh
umask 077
printf '%s\n' 'the-secret' > /etc/lite-client/auth
chmod 0600 /etc/lite-client/auth       # if the file already existed with other permissions
```

Only the first line is read, up to the first CR or LF. An empty file, a line that is too long, or a
file with a NUL byte in it (UTF-16) is refused rather than silently cut.

These three paths are the package's conffiles, so they survive a sysupgrade. If a `*_file` option
points elsewhere, the service warns at every start that the file will not be kept.

## Example: REALITY

Server side (Xray), the parts that matter:

```json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "raw",
      "security": "reality",
      "realitySettings": {
        "target": "www.example.com:443",
        "serverNames": ["www.example.com"],
        "privateKey": "<private key>",
        "shortIds": ["0123abcd"]
      }
    }
  }]
}
```

`xray x25519 -i '<private key>'` prints the matching public key as "Password (PublicKey)".

Router side:

```sh
umask 077
echo '11111111-2222-3333-4444-555555555555' > /etc/lite-client/uuid
```

```
config lite-client 'main'
	option enabled     '1'
	option plane       'reality'
	option node        'server.example.net'
	option port        '443'
	option sni         'www.example.com'
	option public_key  '<public key>'
	option short_id    '0123abcd'
	option flow        'xtls-rprx-vision'
	option udp_port    '19100'
	list clients '192.168.1.0/24'
```

## Example: Hysteria2

Server side (hysteria), the parts that matter:

```yaml
listen: :443
tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.pem
auth:
  type: password
  password: the-account-password
obfs:
  type: salamander
  salamander:
    password: the-obfs-password
```

On the server, get the pin:

```sh
openssl x509 -in /etc/hysteria/cert.pem -outform der | sha256sum
```

Router side, with the `lite-client-hysteria` package:

```sh
umask 077
echo 'the-account-password' > /etc/lite-client/auth
echo 'the-obfs-password'    > /etc/lite-client/obfs
```

```
config lite-client 'main'
	option enabled     '1'
	option plane       'hysteria'
	option node        'server.example.net'
	option port        '443'
	option sni         'server.example.net'
	option pin         '<64 hex characters>'
	option rate        '12500000'
	option udp_port    '19100'
	list clients '192.168.1.0/24'
```

For port hopping, write the port as a range and give the server a firewall redirect from that range
to the one port it listens on (hysteria's documentation describes the rule):

```
	option port        '20000-50000'
	option hop_seconds '30'
```

For Gecko instead of Salamander (`obfs.type: gecko` on the server), put the Gecko password in the
obfs file and add the sizes the server uses:

```
	option gecko       '512-1200'
```

## Mapping a share link by hand

There is no importer. Take the fields from the link like this.

**`vless://`**, as in
`vless://UUID@HOST:PORT?type=tcp&security=reality&sni=SNI&pbk=KEY&sid=SID&fp=firefox&flow=xtls-rprx-vision#name`:

| link | option |
|---|---|
| `UUID` (before `@`) | first line of `/etc/lite-client/uuid` |
| `HOST` | `node` |
| `PORT` | `port` |
| `sni` | `sni` |
| `pbk` | `public_key` |
| `sid` | `short_id` |
| `flow` | `flow` (absent: `none`) |
| `security` | must be `reality` |
| `type` | must be `tcp` or `raw`; XHTTP is not supported by the tunnel |
| `fp` | no option: the client always sends the Firefox hello |
| `spx` | no option |

**`hysteria2://`** (or `hy2://`), as in
`hysteria2://AUTH@HOST:PORT/?sni=SNI&obfs=salamander&obfs-password=OBFS&pinSHA256=PIN#name`:

| link | option |
|---|---|
| `AUTH` (before `@`, URL-decoded) | first line of `/etc/lite-client/auth` |
| `HOST` | `node` |
| `PORT` | `port`; a single range like `20000-50000` works, a list with commas does not |
| `sni` | `sni` (absent: the host name) |
| `obfs=salamander`, `obfs-password` | first line of `/etc/lite-client/obfs` |
| `obfs=gecko`, `obfs-password` | the same, plus `gecko` set to the server's sizes |
| `pinSHA256` | `pin`, with colons removed and in lower or upper case |
| `insecure=1` | no equivalent; use `pin` (or `pin '-'` knowingly) |

If the link has no `pinSHA256`, compute the pin on the server as shown above.

## What the service installs

On start, after all checks pass:

- `lc-tunnel` under procd, respawned without limit, five seconds apart. On the Hysteria2 plane a
  server that does not answer at start makes the tunnel exit, as the reference client does, and
  procd tries again.
- A routing rule `fwmark 0x1000000/0x1000000 lookup 104 priority 102` and a local default route in table 104.
- An nftables table `inet lite_client` with a prerouting chain at mangle priority:
  - packets that belong to an existing transparent TCP socket are marked and accepted;
  - traffic to the server's own addresses is left alone. A host name is resolved once at start for
    this, so an address the name moves to later is exempted at the next start;
  - for each entry in `clients`: TCP 80 and 443 are sent to `listen_port`, and UDP 443 to `udp_port`
    if set.

The table is loaded with one `nft -f`, so a bad entry cancels the whole ruleset rather than leaving
half of it in place. Stopping the service removes the table, the rule and the route.

While the service is running, traffic from the listed clients to ports 80 and 443 either goes
through the tunnel or goes nowhere. If `lc-tunnel` is down and procd is restarting it, that traffic
is dropped, not sent directly. Everything else leaves the router as usual: other ports, DNS, UDP when
`udp_port` is unset, and all IPv6. The service logs the last two at every start.

## External marking: empty `clients`

With `clients` empty, the service still starts the tunnel, the transparent-socket rules, the server
exemption and the routing rule, but intercepts nobody by address. This is for setups where another
firewall component decides what goes into the tunnel, for example by domain sets. That component
has to:

- tproxy the chosen TCP traffic to `listen_port` (and UDP to `udp_port`) on the router, and
- add reserved mark bit `0x1000000` before TPROXY, preserving other bits, so that the routing rule delivers it locally.

A minimal nftables example of such a rule, in your own table:

```
ip daddr @proxied_v4 tcp dport { 80, 443 } meta mark set meta mark | 0x1000000
ip daddr @proxied_v4 tcp dport { 80, 443 } tproxy ip to :19099 accept
```

The mark and table number are fixed in the service script (`FWMARK`, `RT_TABLE`). They were chosen
outside the usual mwan3 and Tailscale masks. Custom mark allocations must still
be checked. Priority 102 delivers selected packets before mwan3 member rules.

## TCP memory tuning

Before starting the tunnel, the service raises the kernel's TCP memory limits, because on small
routers the defaults cap a single download well below what the link and the CPU can do. It does this
on every start:

- It reads the kernel's own `net.ipv4.tcp_mem` once after boot and keeps it in
  `/var/run/lite-client.tcp_mem`, so repeated restarts do not compound.
- The new pressure threshold is three times the kernel's, but never more than half of the
  `MemAvailable` at that moment. The low and high marks keep the kernel's proportions (three
  quarters and one and a half of the threshold).
- The maximum of `tcp_rmem` and `tcp_wmem` becomes half of the threshold in bytes, capped at 32 MB.
  Their minimum and default values are left alone.
- If half the free memory is not more than the kernel's own threshold, nothing is changed.

It logs the result as `tcp memory: LOW PRESSURE HIGH pages (...), a socket up to N bytes`. If the
kernel refuses (a read-only `/proc`), the tunnel still starts, with the kernel's limits. The settings
last until reboot.

Measured on an MT7621 with 118 MB of RAM: the kernel's own limit for one socket there is 0.9 MB,
which holds HTTPS over REALITY at about 33 Mbit/s on a 110 ms path; with the tuning, the same
download ran at 66 to 69 Mbit/s. On an AX3000T the default pressure threshold made the kernel drop
already-acknowledged out-of-order segments, and the server resent a quarter to two fifths of every
download.

## Running `lc-tunnel` by hand

For testing, stop the service (which also removes the rules) and run the tunnel in the foreground.
`lc-tunnel` with no arguments prints its usage. The service builds these command lines:

```sh
# REALITY
lc-tunnel /etc/lite-client/fingerprint.fpt NODE PORT SNI PUBLIC_KEY SHORT_ID @/etc/lite-client/uuid LISTEN_PORT \
    -f xtls-rprx-vision [-u UDP_PORT] [-w WORKERS]

# Hysteria2
lc-tunnel -H NODE PORT SNI @/etc/lite-client/auth @/etc/lite-client/obfs LISTEN_PORT \
    -p PIN [-r RATE] [-j HOP_SECONDS] [-g MIN-MAX] [-c off] [-u UDP_PORT] [-w 1]
```

On the Hysteria2 plane the obfs argument is `-` when there is no obfuscation. Without the service's
rules nothing is intercepted, so this is mostly useful for seeing whether the handshake completes.
