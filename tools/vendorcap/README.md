# vendorcap — taking the reference's own bytes, so the tests hold a measurement

`tools/fp` already does this for one thing: it renders uTLS's ClientHello and diffs ours against it
byte for byte, and `test-fphello` runs that comparison in the gate. Every other format in this tree
was pinned by a person reading the vendor's source and writing the layout into a test.

That is not the same kind of check, and on 2026-08-25 the difference showed. The QUIC hello offered
twelve signature schemes where the reference offers seven and omitted `signature_algorithms_cert`
entirely — the right constant taken out of the wrong context (uTLS keeps the unfiltered list because
its callers are browser fingerprints that really do offer TLS 1.2; Go deletes PKCS#1 and SHA-1 when
the minimum version is TLS 1.3, and QUIC has no minimum below it). A test written from the same
reading would have agreed with the bug.

These two programs take the bytes instead.

| tool | what it captures | what it settled |
|---|---|---|
| `qstand` | QUIC transport parameters, and the parsed ClientHello **including extension order** | the hello of the Hysteria plane; the transport parameters (set and order identical to quic-go, four window values deliberately lower) |
| `qstand/run.sh` | the Initial flight of the reference client and of ours, side by side: every CRYPTO frame the server read, in arrival order | the ClientHello layout — one cut at the second half of SNI, written last (patches/ngtcp2/0005) |
| `vlesstrap` | the plaintext a VLESS client writes: request header, Vision frames, xudp frames | the 52-byte VLESS request; a whole Vision padding frame; the twenty-byte xudp metadata and its global id |

Two more programs live here that do NOT capture reference bytes, and the distinction is worth keeping
straight: they measure this client rather than pin the reference's formats. They are in this
directory because they carry the same rule — the recipe and the traps live in the file header, so a
measurement can be repeated instead of remembered.

| tool | what it measures |
|---|---|
| `standsrv` | the target end: an HTTP source of arbitrary size and a UDP echo, so that both ends of a measurement sit behind the node |
| `udpbench` | the datagram path: N packets of size S from ONE socket, counted back off the echo |

`nativeclient/native-policy-soak.sh` exercises coexistence with the platform's
DNS/policy workload. Use an explicitly designated laboratory router: it configures
the installed full LiteClient package, then stops it and retains the lab profile.
The original UCI file is saved in the private staging directory. It requires
`LAB_ROUTER_ACK=1`, the expected board/binary/service hashes, frozen inputs and staged
`settings.sh`, credentials, reference-peer responses and DNS fixtures.
`policy-seed.json` is a frozen canonical metadata snapshot. A previously warmed
snapshot is validated, rendered and loaded into the owned table, allowing a
driver retry without repeating the DNS warmup. Empty snapshots are warmed with
actual A/AAAA queries before the timed phases.

The workload warms 1,375 A/AAAA owners, runs four checked TCP/TLS downloads and
64 nonce UDP echoes every ten seconds, and alternates policy checkpoints,
selection changes and a failed canonical commit while both native planes run.
Copied router helpers keep their implementation; only temporary paths, the
owned nft namespace and the DNS service boundary are isolated. Process/config
readiness still uses the actual dnsmasq sockets. This measures coexistence with
cached destinations through loopback TPROXY; it does not qualify LAN/NAT, a real
control-plane delivery or an owner firewall reload.

Replay an unpacked private bundle with
`python3 tools/vendorcap/nativeclient/policy_soak.py DIRECTORY`. It requires the
frozen `plan.json`/`stage/`, device results and peer receipts, including the final
OOM and original-DNS process observations. The driver captures those before/after
observations, restores the declared selection and exports the final canonical/kernel
snapshots. Either terminated workload fails the driver at its next liveness check.
The resource observer also checks for new kernel OOM events during the run;
its termination fails the same liveness check even if procd restarts the victim.
Each kernel observation uses private temporary files, so a second observer
cannot truncate its snapshot. The current driver runs Hysteria before REALITY;
the frozen plan must declare that order. Replay accepts both complete orders.
DNS restart timeouts are counted;
missing traffic, a restarted native process, incomplete policy churn or corrupt
payload evidence is rejected. Resource samples carry no RAM admission threshold
and are not a throughput comparison.
Evidence schema `native-policy-coexistence-v2` records the observer's explicit
20-second TCP connect/UDP receive and 30-second TCP total budgets. The traffic
cadence, minimum burst count and observation-gap checks are unchanged. A shorter
observer deadline can expire before a valid dial/handshake completes: the pinned
Xray `DefaultSystemDialer.Dial` permits 16 seconds
(`vendor/Xray-core/transport/internet/system_dialer.go`), and quic-go's default
total handshake budget is twice its five-second idle budget
(`vendor/quic-go/config.go`, `handshakeTimeout`). Historical v1 bundles require
their frozen v1 analyzer; they are not silently reinterpreted with new deadlines.
Both device drivers require `flock` and share one RAM lock because they configure
the same installed client. Use one fresh staging directory per attempt. After a
failed attempt, verify the exported archive off-device before removing its old
staging directory: retained payloads and intermediate snapshots consume tmpfs RAM
and must not accumulate into the next measurement. Preserve the original UCI
backup separately when the device still needs restoration.
Process-tree cleanup reads `PPid` from `/proc/*/status`: some OpenWrt kernels
omit `/proc/PID/task/PID/children`. A procd PID is accepted only as a positive
number; a transitional `null` must produce no PID during recovery polling.
The process inventory must retain every PID in the stable service core. Other
same-name invocations are reported separately; this capture does not record their
parent PIDs or command lines.
The selected domain list must contain the plan's actual unique owner count.
Final canonical metadata and both kernel address families must match that list,
including owner hashes, populated A/AAAA sets and exact union contents. Empty or
partial starting seeds are permitted; they do not substitute for the final warm
workload. Policy operations must start inside their plane's timed traffic window,
remain ordered, and finish before that plane's final observation ends.

`nativeclient/native-lan.sh` adds a separate, opt-in correctness check on the
dedicated lab router. A veth network namespace supplies a client through `br-lan`;
the existing firewall performs normal WAN NAT before either native plane starts.
Both planes then exercise selected/direct/reselected destinations and real fw4
reloads, with byte-checked TCP/TLS and nonce UDP echoes. The full package, working
`ip netns`, `flock` and a veth module matching the installed kernel are prerequisites;
the driver does not install packages. Its private settings explicitly select the
board, client executable/service hashes, LAN gateway/client address and reference peer.
Do not run this on an owner router: it reloads the real firewall and retains the
disabled lab profile. The driver serializes instances with a RAM lock and removes
its namespace, veth, nft table, routing rule and route before comparing snapshots.

Replay its `plan.json`, frozen `stage/`, `device/` and `peer/` with
`python3 tools/vendorcap/nativeclient/lan_path.py DIRECTORY`. The peer must record
HTTP source/path/TLS/body hashes and ordered UDP source/nonce hashes, so a valid
download received directly cannot stand in for a selected proxy path. The plan
hashes every device input and the reference executables, configuration and stand
driver. This checks the kernel LAN/NAT path, not a physical LAN cable or real API
delivery, and makes no throughput claim. `soak_probe.c` accepts an explicit IPv4
target as `probe udp PORT IPV4` and an optional 1–60 second receive budget as
`probe udp PORT IPV4 SECONDS`; the default remains loopback with five seconds.
Xray's `freedom` outbound blocks private destinations by default for VLESS
(`vendor/Xray-core/proxy/freedom/freedom.go`, `getDefaultFinalRule` and
`Handler.matchFinalRule`). A LAN fixture must explicitly allow only its exact
private peer destination in `finalRules`, in addition to any loopback fixture.
An accepted VLESS request alone does not prove that the outbound was allowed.

Each file's header carries its own recipe, the configuration that matters, and the traps. Read it
before running — most of the ways to get a confident wrong answer are written there.

## What is frozen where

| frozen in | taken with | note |
|---|---|---|
| `test/qhello/test_qhello.c` | `qstand` | extension order and both signature-algorithm lists |
| `test/vless/test_vless.c` | `vlesstrap` | the request header, byte for byte |
| `test/vision/test_vision.c` | `vlesstrap` | a real frame, fed to **our reader** rather than compared to our writer |
| `test/post/test_post.c` | `nodealert` | what the client makes of every record the node sends once the handshake is over |
| `test/fetch/test_fetch.c` | `spiderredir` | what the spider sends after the first request: redirects, windows, cancels, and where it sends nothing |
| `src/vless/xudp.h` | `vlesstrap` | the metadata length and the global id, in prose — see below |
| `src/quic/params.h` | `qstand` | the transport-parameter comparison, in prose |

The last two are prose rather than assertions on purpose: what they record is why this client
DIFFERS, and an assertion pinning a deliberate difference tells the next reader nothing about
whether it is still deliberate.

## The rule these exist to serve

A test that builds a frame with its own writer and reads it back with its own reader checks the two
halves against each other. It keeps passing when both are wrong in the same way, which is exactly
what happens when a format was transcribed once and the transcription was off. Where a vector can be
taken from the reference, take it.

⚠️ And when a capture ends mid-frame, retake it. The Vision padding length is drawn per connection —
one capture came out 134 bytes and was cut off by a 256-byte read, the next drew 108 and fit.
Completing the first by hand would have turned a measurement back into a transcription, which is the
thing being avoided.

## The third stand: our client against a reference SERVER

The two programs above capture what a reference CLIENT sends. They say nothing about the other
direction — the frames a node sends back, which our reader has to handle. That direction cannot
usefully be pinned as a vector: the server pads with its own draw, sends its uuid once by its own
rule, and moves to End or Direct on its own schedule. What settles it is running against the real
thing.

No new program is needed. Xray builds a REALITY **server** from `vendor/Xray-core`, and `lc-fetch`
is already a REALITY client:

```sh
/tmp/xray x25519                       # PrivateKey: … / Password (PublicKey): …
```

Server config — `vless` inbound, `decryption: none`, the client's uuid with
`flow: xtls-rprx-vision`, and `streamSettings.security = "reality"` with `target`,
`serverNames`, `privateKey`, `shortIds`. Then:

```sh
./build/lc-fetch package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru \
    <PublicKey> <shortId> <uuid> example.com:80 xtls-rprx-vision
```

Measured 2026-08-25: `REALITY authenticated`, `target replied: HTTP/1.1 200 OK`,
`tunnel carried 868 bytes back`, and the server logged `accepted tcp:example.com:80` with nothing
else. That is the whole path — hello, REALITY authentication, the VLESS request, Vision in both
directions, and the switch out of padding — against the implementation this client exists to be
indistinguishable from.

⚠️ THE FLOW ARGUMENT IS OPTIONAL TO lc-fetch AND NOT OPTIONAL TO THE SERVER. Left off, the server
answers `account … is rejected since the client flow is empty` and the stream opens and then says
nothing — which our client reports as "nothing came back through the tunnel". That is the same
silence a wrong uuid, a wrong target and a dead node produce, so a stand run without the ninth
argument looks like a broken client rather than a misconfigured test.

## The fourth stand: BETWEEN two references

`vlesstrap` with a second argument stops terminating and starts relaying: it accepts the client with
our certificate, opens its own TLS to a real Xray server, and copies, printing both directions.

```sh
/tmp/vlesstrap 127.0.0.1:14460 127.0.0.1:14471 &      # listen, upstream
```

The client pins the trap's certificate, so a man in the middle is exactly what is wanted: both ends
are the reference and only the wire between them is ours to read. Server side is a plain
`vless` + `security: tls` inbound with the same uuid and `flow: xtls-rprx-vision`; drive it with
`curl --socks5-hostname … https://…` so that the inner traffic really is TLS.

This is the only mode that sees a whole session. A trap that merely terminates never lets the inner
handshake complete, so `longPadding := trafficState.IsTLS` never becomes true and the capture stops
after the client's first flight. Measured through the relay, in one session:

| direction | frame | total |
|---|---|---|
| server, first | VLESS response `00 00`, then content 1420 padding 174 | — |
| client | content 80, padding **921** | 1001 — the long branch |
| client | command 2 (Direct), 123 + 1159 | 1282 |
| server | command 2, 553 + 450 | 1003 |

921 = 101 + 900 − 80, so the draw was 101 out of 500: the reference's formula, to the byte. Those
ranges are now asserted in `test/vision`.

⚠️ WHAT THIS STAND STILL CANNOT DO: put OUR client through it. `lc-fetch` speaks REALITY only — the
public key and short id are required arguments — and the trap terminates plain TLS. Reading our own
session on the wire would mean terminating REALITY, i.e. writing its server side. Until then the
sequence-level behaviour (when padding stops, how many packets the filter looks at, which command
ends it) is held by reading with citations — `NumberOfPacketToFilter: 8`
(vendor/Xray-core/proxy/proxy.go:145) against LC_VISION_FILTER_PACKETS 8, `if *isPadding` (:361) against
`s->vision.padding_out`, :384 against the `!is_tls12_or_above && packets_to_filter <= 1` arm — and not by measurement.

## The fifth stand: the TRANSPARENT path, on a real kernel

The four above exercise formats. None of them touches the part that decides whether a household has
an internet connection: tproxy, the mark, the reply socket bound to the address the client was
talking to. That path had never been run anywhere but a router.

⚠️ It cannot be run on a Windows workstation at all — see docker/Dockerfile.net for the measurement.
It runs on any real Linux host with `nft_tproxy`; the recipe below was built on a node.

Three tiers, so that the traffic is FORWARDED and therefore passes PREROUTING — locally generated
packets skip it, which is why a client on the same host proves nothing:

```
host (reference Xray server on 10.99.0.1:14470)
  └─ veth ─ netns lcs-b : lc-tunnel + tproxy rules, ip_forward=1
              └─ veth ─ netns lcs-a : the client
```

The mangle chain in lcs-b accepts traffic to the node's own subnet first (otherwise the tunnel's own
upstream is captured), then marks and tproxies TCP to 19999 and UDP to 19998, with counters — those
counters are how you tell "the client never sent" from "the client sent and we dropped it".

⚠️ THREE TRAPS, each of which cost a run:

  - `pkill -f "srv.json"` MATCHES THE SHELL RUNNING IT. The command line of the `bash -c` that
    invokes pkill contains the pattern, so the shell kills itself and the command times out with no
    output. `[s]rv\.json` does not help if the same command line also mentions the file. Get the pid
    separately — `pgrep -x xray` plus `readlink /proc/$p/cwd` — and kill by number.
  - `setsid` LOSES CAP_NET_ADMIN, and the tunnel then refuses with "cannot listen on 19999
    (transparent mode needs CAP_NET_ADMIN)". `nohup … &` keeps it.
  - THE REALITY TARGET MUST BE REACHABLE FROM THE SERVER'S HOST. A node in the US cannot reach
    www.avito.ru; the server then stalls with nothing in its log at any level, and the client
    reports "gave up while shaking hands" — which reads as a client fault and is a stand fault. Use
    something the host can actually open, and check it with `nc -z` before blaming anything.

Measured 2026-08-25 once it was right: TCP through the tunnel returned 200, both 8.8.8.8 and
1.1.1.1 answered through it, zero give-ups, and the server logged `accepted udp:8.8.8.8:53` and
`accepted udp:1.1.1.1:53`.

**The baseline this exists to establish:** two destinations from one client, measured as the delta
in the tunnel's own `waits to open … (of N)` counter across the two queries, is **2** — one VLESS
stream per destination. The reference carries both on ONE stream and names the destination in each
frame. When that changes here, this number becomes 1, and that is the whole test.

## The sixth stand: how fast, and the ways that question answers itself wrongly

The five stands above ask whether this client is CORRECT. None of them asks how fast it is, and
throughput is the one property a user notices without being told to look.

```
node (a VPS)                               router or workstation, behind the tunnel
  standsrv 0.0.0.0:18080 0.0.0.0:18081  ─────  curl http://<node-public-ip>:18080/bytes/50000000
                                        ─────  udpbench <node-public-ip>:18081 2000 1200
```

Both ends behind the node on purpose: a measurement against something on the open internet measures
the internet's congestion control and peering, not the tunnel.

⚠️ FOUR WAYS TO GET A CONFIDENT WRONG NUMBER, each of which cost a run:

  - **Naming the target privately.** Xray's `freedom` outbound refuses private destinations. The
    node logs `blocked target: tcp:10.99.2.1:18080` and the client reports only that nothing came
    back — which reads as a broken client and is a misconfigured stand. Bind anywhere; ADDRESS the
    public IP.
  - **A loop over `dig` as a multi-destination test.** `dig` opens a fresh socket per query, so N
    queries are N clients, not one client with N destinations. That is the opposite of the case the
    session model exists for. `udpbench` uses one socket for exactly this reason.
  - **Sending the datagram burst flat out.** It lands while the stream is still opening, the queue
    overflows, and the drop policy gets reported as the throughput. The reference drops the same way
    by design — `pipe.DiscardOverflow()` with a 16 KB limit (app/proxyman/inbound/worker.go:289) —
    so this is a property of the thing measured, not something to tune away.
  - **Reporting the through-tunnel number alone.** UDP echo loses packets on any real path. Run the
    same command against the target directly and subtract, or the network's loss is charged to the
    client.

⚠️ AND THE PORTS ARE EXPOSED WHILE THIS RUNS. 18080/18081 on a node's public address are open to
everyone for the duration. Close them when the measurement is done.

### What the reference itself loses on a burst (measured 2026-08-26)

The third trap above says a flat-out burst measures the drop policy rather than the throughput. That
was read off `pipe.DiscardOverflow()` and asserted. It has now been measured, against the reference
CLIENT rather than ours: Xray 26.7.28 built from source, run on a workstation, with a
`dokodemo-door` UDP inbound and a `vless` + `reality` + `xtls-rprx-vision` outbound to a stand
server, whose `freedom` outbound reaches `standsrv`'s echo on the same host.

400 packets, sent flat out, at three sizes:

| packet size | 16384 / size | came back | bytes back |
|---|---|---|---|
| 400 | 40 | **41** | 16 400 |
| 800 | 20 | **21** | 16 800 |
| 1200 | 13 | **14** | 16 800 |

The count tracks `16384 / size` at every size, and the VOLUME returned is ~16 KB regardless — which
is `pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))` (app/proxyman/inbound/worker.go:289)
observed from outside, rather than deduced from the source. The consistent +1 is the datagram already
taken off the pipe while the rest queue behind it.

Controls, without which the number means nothing:

  - **Direct to the echo, no tunnel:** 393 of 400, 98.2%. The path itself loses 7.
  - **Same burst, 5 ms between sends:** 332 of 400, 83%. So this is a queue, not a ceiling.

⚠️ WHAT THIS DOES NOT SHOW. Each `udpbench` run binds a fresh source port, so Xray sees a new client
and a new session every time; both runs above are COLD. Whether an established session drains
differently is untested — testing it needs a client that reuses its port.

**Why it matters here:** `UDP_PEND_BYTES` in lc-tunnel is 16384 to match that pipe. This is the
measurement that makes the match a fact about observable behaviour rather than a copied constant.

## The seventh stand: the uplink's write shape, against the reference client

`wireshape/run.sh` runs the reference Xray client (dokodemo-door in, VLESS + REALITY + Vision out) and
this client against one vendored REALITY server, each under strace, through the same six scenarios,
and prints the size of every write(2) towards the node in order. Recipe, scenarios and traps are in
the script's header.

What it settled on 2026-09-15, each a difference the outbound's source did not show:

| scenario | reference | this client, before |
|---|---|---|
| handshake end | CCS + Finished in one write, the request in the next | both in one write |
| client silent 1.2 s | 500 ms, then **the header alone** (66 bytes) | header and an empty padded frame at once |
| six datagrams during the handshake | all six with the header, one buffered write | the header, then one record per datagram, no Vision |
| 300 KB upload | records written one per write(2); readv buffers 1, 2, 4… | all records of a read in one write |
| end of an HTTP exchange | no FIN either way; close_notify one timer (1 s) after the node's end | FIN to the node at the client's end, close_notify into a shut socket (`-1`) |

The second row is the one to remember: outbound.go writes a padded frame on `buf.ErrReadTimeout`, but
the dispatcher's TimeoutWrapperReader times out with `nil, nil`, so that branch never runs. The
fourth row's later shape (how many 4118-byte halves follow the end of padding) depends on how much
the kernel had queued when each reader looked, and varies with the speed of the reader.

## The tenth stand: what the client says back when the node's records go wrong

`nodealert/run.sh` puts vendor/REALITY itself — the server a node runs — in front of the reference
Xray client and this one, with `hook.go` compiled into a copy of the package so that the node can
seal any record and write past the record layer. Each connection misbehaves one way once the VLESS
request is in, and the node reads what the client says back WITH THE CLIENT'S KEY: the alert's number
is compared as well as the records a path sees. Recipe, scenarios and what each line means are in
the script's header; the verdicts are frozen in `test/post/test_post.c` against `src/tls/post.c`.

What it settled on 2026-09-24, 46 scenarios, the two clients alike in every one:

| the node sends | reference | this client, before |
|---|---|---|
| a ChangeCipherSpec in the clear; a header with version 0x0301 or a length over 2^14 + 256; a record that does not open | its alert — 10 or 50 or 22, 70, 22, 20 — then close_notify | close_notify alone, for every one of them |
| a session ticket, whole or cut across two records | read and ignored | dropped unread |
| one that does not unmarshal; an empty handshake record; a Finished; a record of a type TLS has not got | 10 | dropped, the connection went on |
| a handshake type uTLS has no message for | 10 **twice** | dropped |
| a message declared over 64 KiB (256 KiB for a Certificate) | 80, on the four bytes that declare it | dropped |
| 33 records that carry nothing | 10 | dropped, forever |
| its own alert or close_notify | the end — before the VLESS response, of the session at once | dropped, the connection went on |
| a KeyUpdate, its own write key moved on after it | the read key moved on; asked for an answer, a KeyUpdate back (23/22 on the wire) and the write key moved on | the connection closed |
| a record of nothing but a tag; one sealed under a handshake header; one that opens to 2^14 + 2 | an empty record, read; 10; 22 — each once the tag has verified | 20 for all three, before opening |

The first row is what anybody on the path can produce; the rest take the node's key.
And the stand found two faults in
the change itself before it was committed, which is the case for keeping it: every refusal went out
as alert 0 — close_notify, the right length on the wire — because an argument list read the alert
before the call that set it; and a close_notify ahead of the VLESS response was answered as a
half-close, where the reference ends the session. Neither shows in any test that does not have the
other end. Of six mutants of the lc-tunnel side it catches five, the sixth removing a guard whose
state loopback does not produce — see the top of records_ready; of five in KeyUpdate (the label,
the answer, either key not moved, the answer sealed after the move) it catches all five.

On 2026-09-25 it got `kufull`: a KeyUpdate asking for an answer while the client's way to the node
is full — the probe's `tcpup` pushes 48 MB behind its request and the node reads none of it for two
seconds, then asks, then reads. The reference's answer waits for the write lock the stuck Write
holds and goes out once the node reads; the node compares how much of the upload arrived, how many
answers it took (hook.go's StandReadGens, since the answer is somewhere among 48 MB of records) and
how the client ended. It found a fault that predates the waiting: the answer used to be queued and
then FLUSHED from the read side, and a flush that emptied the queue in the middle of a multi-buffer
write left that write with nothing to resume it — the reference carried all 48 MB, this client 3 MB
and then sat there, the build before the fix included. With the answer written as every record is
(conn_write), the tree matches; so does a build where the answer is forced to wait for an empty
queue, which is the path a full queue takes. Of four mutants it catches all four: the old refusal
under that forcing, the settle on the write side removed, the key moved before the answer is sealed,
and the unfixed flush (HEAD at the time).

Later the same day it went into the handshake as well, for the one thing a stock node never sends:
application settings (ALPS). Five calls spliced into the copy of vendor/REALITY — named in
`hook.go` — make the node put h2 and ALPS into its EncryptedExtensions and take the client's answer
into the transcript before it checks the client's Finished. uTLS answers the settings with an
EncryptedExtensions of its own after the server's Finished, ten bytes under the server's codepoint;
this client did not, and a server speaking ALPS would have seen one message fewer and a Finished
over a different transcript. Now both send `08 00 00 06 00 04 44 cd 00 00` (and `44 69` under the old
codepoint), both Finisheds verify with it hashed in, and settings with no protocol chosen get
unsupported_extension from both. Two mutants — no answer, and the answer left out of the transcript
— it catches both; the rule that the last of two codepoints stands is test/alert's.

## The eleventh stand: what the spider sends when the site answers with a redirect

`spiderredir/run.sh` sends the reference Xray client and this one down the stranger's path to a node
whose target is x/net's own HTTP/2 server, which answers each scenario with a redirect and prints
everything the client wrote on the connection, frame by frame, header lists in order. Recipe and
scenarios are in the script's header; the behaviour is frozen in `test/fetch/test_fetch.c` against
`src/reality/fetch.c`.

What it settled on 2026-09-24, sixteen scenarios, six connections of each client in each:

| the site answers | the reference, and this client since | this client, before |
|---|---|---|
| a redirect on the same host — relative, absolute, with dot segments, scheme-relative, 303 | HEADERS on stream 3: the first request's fifteen headers and a referer, a block of 44 bytes against the first one's 464 | nothing after the first request |
| a redirect to itself, for ever | ten requests, streams 1 to 19, and no eleventh | nothing |
| a body of 1000 bytes, with the answer or a read after it | read, nothing handed back, then stream 3 | nothing |
| a body of 5000 | WINDOW_UPDATE +5000 then stream 3 — or, when it has not all come, RST_STREAM(CANCEL), stream 3, and +5000 as it arrives: two connections in six, in both clients | nothing |
| a gzip body of 31 KB | read in five fills of 4096, to where flate's window fills; the other 10978 handed back, then stream 3 | nothing |
| another host; a subdomain of this one | a second preface mid-stream, then stream 1 again from a fresh encoder — without the cookie; with it | nothing |
| http; no Location | nothing | nothing |

The byte count of every connection is the reference's in every scenario, give or take the Chrome
version each process draws. One difference stands, in `gzbody`: this client cancels the stream on
every connection and the reference on none to two in six. The reference inflates 32 KB before it
gets to Close, and the site's END_STREAM is read in the meantime; this closes the moment the input
is in. A race inside the reference itself, on a redirect whose body inflates past 32 KB.

The stand corrected the model before it was committed: the slurp over gzip stopped where a deflate
block ended — three fills — and Go's flate hands out nothing until its window fills or the stream
ends (GOROOT/src/compress/flate/inflate.go:678-686); the reference read five.

The second fetch, later on 2026-09-24, took the rest of the model out of the way and ran the stand
again: sixteen scenarios, six connections of each client in each, **the same byte count on every
connection of every scenario**. What changed, and what the stand saw of it:

| | the reference | this client, first fetch | second fetch, one read before Do | second fetch |
|---|---|---|---|---|
| `gzbody`: RST_STREAM(CANCEL) on the redirect | none to two in six | six in six | none in six | none in six |
| `bigbody`: RST_STREAM(CANCEL) — its END_STREAM a record behind the body | two or three in six; one in six today | two or three in six | six in six | three in six |
| the first request carries a HEADER_TABLE_SIZE update — the site's SETTINGS read first | 4 in 96, and 0 in 96 on the next run | never | never | 1 in 96 |

The gzip body is read by Go's own reader now, transcribed: compress/gzip over compress/flate over
bufio (`src/core/gozip.c`, held to Go by `test/gozip` on 8262 cases), where the first fetch tracked
zlib to where flate's window fills — which is right for a page and wrong for a sync flush, a stored
block past four kilobytes, a trailer or a second member. And Do acts only once the socket has been
read dry: the reference's readLoop goes on reading while its goroutines wake, and a site whose
END_STREAM follows its body by a record — `bigbody`'s did — has it read before Do closes the stream
more often than not. The first request is written at that same point, after whatever had already
arrived, which is how a site's SETTINGS gets in ahead of it in a few connections in a hundred in both
clients. The races stay races; they are now the same races.
