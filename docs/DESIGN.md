# Design notes

How lite-client is put together and why. For building see [BUILD.md](BUILD.md); for the options on a
router see [CONFIG.md](CONFIG.md). Two documents in the top directory go deeper on specific subjects:
[DIVERGENCES.md](../DIVERGENCES.md), the list of every known place where this client behaves
differently from its reference, and [CONCURRENCY.md](../CONCURRENCY.md), the record of how work was
spread over several cores and what each step measured.

The source review of the owner's suggested Rust client is recorded in
[UNBIHEX.md](UNBIHEX.md), with a fixed revision, useful implementation mechanisms
and observable differences from LiteClient's pinned references.

## The problem it solves

This is a purpose-built client, not a port of an engine. It exists for routers where `sing-box` does
not fit. Measured on a Xiaomi Mi Router 4A Gigabit (`ramips/mt7621`, `mipsel_24kc`, OpenWrt 25.12.5)
on 2026-08-10:

| | |
|---|---|
| writable flash (`rootfs_data`) | 7 360 KB, of which 5 360 KB free |
| `MemTotal` | 118 768 KB, `MemAvailable` 34 000 KB |
| `sing-box-tiny` | 27 MB installed, RSS ~29 MB: does not fit either way |
| target for this client | ≤ 1.5 MB on flash, ≤ 8 MB RSS |

The flash target holds (see "Sizes" in [BUILD.md](BUILD.md#sizes)). The RSS target was set before
the Hysteria2 plane took the reference's receive windows (8 MiB per stream, 20 MiB per connection)
and its threads. Earlier REALITY measurements were 2.5 to 4.5 MB on both routers; they do not
establish the resource cost of concurrent spider sessions introduced later. Hysteria2 does not
always: a fast download on the AX3000T peaks at 9 to 11 MB, against 24 to 40 MB for the hysteria
client on the same downloads.

The scope is narrow on purpose: a transparent (TPROXY) inbound, one outbound, direct and block. No
server side, no routing engine, no JSON config. Traffic selection stays in nftables and whatever the
router already uses to pick hosts, and credentials stay in files under `/etc/lite-client`. It is
wire-compatible with a stock Xray or hysteria server. It is not config-compatible with sing-box or
Xray.

## Two planes, two packages

The outbound is one of two "planes", chosen at build time by the `HYSTERIA` switch and shipped as two
packages. A household uses one server over one protocol, and the QUIC stack costs about as much flash
again as everything else together.

**VLESS with XTLS-Vision over REALITY, on raw TCP.** Datagrams travel as Xray's xudp over Mux.Cool
(`src/vless/xudp.h`): one stream per LAN client carrying every destination, the way a stock client
with Vision sends them. The ClientHello is Firefox's, built from a table captured from uTLS, with the
X25519MLKEM768 key share REALITY now requires. When the server does not recognise the client it
serves the site it masquerades as, and the client then does what Xray does: it verifies that site's
certificate chain and hostname against the router's CA bundle and fetches pages like a browser would
(the "spider", `src/reality/spider.c`).

There is also an XHTTP (HTTP/2) transport for the same outbound, exercised by `lc-xfetch` and not
wired into the tunnel. Vision cannot work over it: the inner TLS records sit inside HTTP/2 frames
where the filter cannot see them.

**Hysteria2 over QUIC.** A QUIC transport built on ngtcp2 and nghttp3, with this project's own crypto
backend in place of OpenSSL's; HTTP/3 authentication; the server's Brutal congestion control towards
the client when a receive rate is stated; relayed datagrams; Salamander and Gecko obfuscation; port
hopping over a range. Like hysteria since 2.11, the client parrots Chrome's QUIC stack unless told not
to: Chrome's ClientHello through uTLS, Chrome's transport parameters, a zero-length source connection
ID, and the packet layout of Chrome's first flight. The patches that make ngtcp2 behave that way are in
[patches/ngtcp2](../patches/ngtcp2/README.md).

REALITY authenticates the server by construction. Hysteria2 authenticates it by certificate: the
reference verifies the chain, and this client, which carries no chain verification on that plane,
requires a SHA-256 pin of the server's certificate instead (or an explicit `-` to run without).

## The reference, and where this differs from it

The rule is that the client does what its reference does: Xray-core with uTLS for REALITY, hysteria
with quic-go for Hysteria2. Behaviour is ported from the reference source and checked against it,
often by running the reference itself (tools under `tools/` build Go programs from `vendor/` and the
tests compare byte for byte).

Where the client does differ, the difference is listed in [DIVERGENCES.md](../DIVERGENCES.md) in
plain words, with a reason: not ported yet, Go's runtime rather than the reference's code, or a
decision made for speed that keeps the wire identical. The code carries a `DIVERGES: <id>` comment at
each such place, and `make check` fails when a mark and the list disagree.

The reference versions are Xray-core v26.10.31 (with REALITY `83f6217`) and hysteria app/v2.13.0 on the
apernet quic-go fork `a10df75c`. Reference upgrades include behavior changes rather than only
renumbered citations. The Hysteria 2.13.0 QUIC hello includes trust_anchors; its fingerprint change
was explicitly accepted by the owner on 6 November 2026. Earlier upgrades established:

- From hysteria 2.11 the client parrots Chrome's QUIC stack by default
  (`DisableChromeParrot`, vendor/hysteria/core/client/client.go:95-103), with its own ClientHello
  through uTLS v1.8.2 (vendor/quic-go/go.mod:8). All of it is on by default here too;
  `option chrome_parrot '0'` is `disableChromeParrot`. The receive windows grow from Chrome's 6 and
  15 MB to hysteria's 8 and 20.
- REALITY `83f6217` turns away a hello without one X25519MLKEM768 share placed before the standalone
  X25519 (vendor/REALITY/tls.go:215-239). The Firefox table meets that. The client reports version
  26.10.31 in the session ID, as Xray does.
- Xray v26.10.31 is built with Go 1.27, so the spider's HTTP/2 is net/http's own client, IDNA is
  Unicode 17, and `net/url` and the redirect-header rule changed. The build image carries Go 1.27.3
  so that the tools generating those tables and vectors run under the same Go.

Git history has the details of each move; [HISTORY.md](HISTORY.md) summarises the project's history.

## Why the fingerprint tooling came first

REALITY's protection rests on the ClientHello being byte-identical to a browser's. A wrong
fingerprint does not break the connection. Traffic flows, tests pass, and the client is simply
visible. Nothing inside the client can notice this, so acceptance is a byte comparison against uTLS,
the same library at the same revision Xray uses, and the tooling for that comparison was written
before the client.

```
cd tools/fp && go build -o fp .
P=$(go list -m -f '{{.Dir}}' github.com/refraction-networking/utls)/u_parrots.go

./fp dump -fp firefox -sni www.example.com              # parse the reference on screen
./fp dump -fp firefox -sni www.example.com -o ref.bin   # raw bytes for comparison
./fp show ref.bin                                       # field-by-field breakdown
./fp diff ref.bin ours.bin                              # non-zero exit on any real difference
./fp diff -shuffled ref.bin ours.bin                    # Chrome 110+ permutes extensions
./fp table -o firefox.json -parrots "$P" ref.bin        # fingerprint table, JSON to read
./fp table -o firefox.fpt -format bin -name firefox -parrots "$P" ref.bin   # packed, for lc-tunnel
./fp check -fp firefox -sni www.example.com -parrots "$P"   # dump, table, build, diff in one go
```

Flags go before the file names. Go's flag package stops at the first argument that is not a flag,
so `./fp diff ref.bin ours.bin -shuffled` never sees `-shuffled`. `-parrots` names the
`u_parrots.go` of the uTLS that `fp` is built against, which `table` reads the base extension order
from. `make fingerprint` runs the same commands for the shipped tables.

`diff` ignores exactly what is random per connection (`random`, `session_id`, the `key_share` public
keys and GREASE values) and compares everything else to the byte. Two dumps of one fingerprint
compare equal; `firefox` against `chrome` reports 8 differences.

### The shipped table

`lc-tunnel` takes a packed table as its first argument on the REALITY plane, and the package installs
`package/files/fingerprint.fpt`, the Firefox profile. The SNI given to `fp dump` is a placeholder:
the table stores `server_name` as a mode and the real name goes in when the hello is built.

Whether regenerating a table gives the same bytes depends on the profile. Twelve regenerations of
`firefox` give one table. Twelve of `chrome` give twelve, because Chrome shuffles its extension order
per hello and the table records the order it saw. Nothing is wrong with such a table
(`src/fp/hello.c` reshuffles per connection anyway), but it cannot be checked by regenerating and
comparing, which is what `check-fingerprint` does.

Firefox was not always reproducible either. uTLS draws the ECH GREASE AEAD identifier per hello
(`vendor/utls/u_ech.go:48`), and the packer used to read it off the rendered hello, so a capture froze
whichever value the coin had just given. `tools/fp` now reads the candidate list off the parrot
instead, so no drawn value is left in the table. With that fixed the table could be gated, and
`check-fingerprint` also asks that `tools/fp/go.mod` and `vendor/Xray-core/go.mod` pin the same uTLS:
a uTLS bump that moves a literal extension body would otherwise leave two consistent snapshots that
both stopped matching what Xray sends.

## Source layout

```
tools/       fingerprint tooling, and the Go generators the tests' vectors come from
src/core/    argument parsing, buffers, randomness, BLAKE2b, IDNA, Go-compatible text helpers
src/fp/      fingerprint tables and the ClientHello built from them
src/tls/     TLS 1.3 by hand: records, AEAD, HKDF, the key schedule, X25519MLKEM768
src/cert/    X.509, far enough to check a chain, a hostname, a signature and a digest
src/reality/ the REALITY authenticator and the spider
src/vless/   the VLESS request, xudp, and the XTLS-Vision filter
src/h2/      HTTP/2 and HPACK, for XHTTP and the spider
src/quic/    the QUIC crypto backend, HTTP/3, QPACK and the Hysteria2 protocol
src/net/     sockets, the event loop, tproxy
src/cmd/     the eight programs (below)
test/        one suite per module, run by `make check`, plus the stands
patches/     changes to ngtcp2, applied at build time
package/     the OpenWrt recipe, its UCI config and its procd service
docker/      the machines all of the above is built and checked on
vendor/      upstream sources, fetched, never committed
```

## The programs

In the order they were needed. Each answers one question the layer below it cannot:

```
lc-hello    builds a ClientHello from a fingerprint table and writes it out, for `fp diff`
lc-probe    one REALITY handshake against a server
lc-fetch    one HTTP request through it, with or without Vision
lc-xfetch   the same over the XHTTP transport, where Vision cannot apply
lc-hy       one QUIC handshake against a Hysteria2 server
lc-hyfetch  one HTTP request through it
lc-hydns    one DNS question through it, which is the datagram path
lc-tunnel   the client itself: tproxy in, either plane out
```

Only `lc-tunnel` is packaged. All eight exit with the same three statuses, defined in
`src/core/args.h`: `0` it worked, `1` the network said no and trying again makes sense, `2` this run
never had a chance (an argument that cannot mean what it says, a secret that cannot be read, or a
server that answered and did not take us for one of its own).

## Secrets

The UUID, the Hysteria2 password and the obfuscation password are passed as `@FILE`, never as text
on the command line: a command line is readable by every process through `/proc`, and procd keeps its
own copy in ubus for the life of the service. The client reads the first line of the file and
refuses a file that is a symbolic link, is not a regular file, belongs to another user, is readable
by group or others, contains a NUL byte (a UTF-16 file, usually), is empty, or does not fit. A
secret that is silently cut short would be worse than one refused: the server answers a wrong
secret with the site it masquerades as, and nothing would say why.

## Workers: several processes

One process saturated 91 % of one core on a four-thread MT7621 while the other three sat idle, so
the work is split across copies of the process. Processes rather than threads, because every connection
borrows scratch buffers that are shared on the assumption of one thread running one event handler at
a time. Separate processes keep that assumption true with nothing shared and nothing locked, and the kernel hands
each connection to one member of an `SO_REUSEPORT` group.

Workers split connections, not one download. A single stream lives in one worker from start to end.
Measured over plain HTTP (no TLS inside, so Vision cannot splice and every byte goes through the
record layer, the CPU-bound case), four downloads at once:

| | aggregate | per stream |
|---|---|---|
| `workers 1` | 20.5 Mbit/s | 655 646 631 625 KB/s, even |
| `workers 4` | 35.3 Mbit/s | 1323 1229 954 910 KB/s, uneven |

1.72x rather than 4x, and the right-hand column shows why: the kernel hashes a connection to a
worker, so four connections do not land one per worker. A household has many more than four and the
spread evens out.

The default is one worker per CPU on the REALITY plane and one on Hysteria2. The first is the
reference's own default: Go schedules over every CPU, so Xray's handshakes spread across cores with
no configuration. Measured on an AX3000T against Xray, twenty connections at once to one server: this
client spent 7.2 ms of CPU per connection to Xray's 9.9, and still reached first byte 30 ms later at
the median, because twenty handshakes queued on one core. Two workers took 47 ms off. Hysteria2 stays
at one because the reference uses one QUIC connection, and a server that limits an account to one
session would close every worker's session but the newest.

With more than one worker the parent stops carrying traffic and supervises: a worker that dies is
replaced without procd needing to know, killing the parent takes all of them (`PR_SET_PDEATHSIG`),
and `kill -USR1` on the parent is forwarded to every worker. Their log lines are prefixed `[wN]`,
because procd logs all captured output under the parent's pid.

## Threads inside a worker

A single connection can still use more than one core. On Hysteria2 there is a reader thread for the
LAN side and a writer thread for the UDP send queue, as the reference's goroutines split the work,
and the receive path hands batches of 32 datagrams to opener threads (one fewer than the CPUs online)
that remove Salamander, header protection and the AEAD ahead of ngtcp2. ngtcp2 still opens every
packet through its own callbacks, and those take a thread's answer only when every input matches, so
nothing on the wire changes. On REALITY, when one read brings several whole records, threads decrypt
them ahead of the loop in the same way. Both are listed in DIVERGENCES.md as deliberate differences
(the reference does this work in one goroutine), and CONCURRENCY.md has the measurements.

The REALITY spider has a separate per-session Do-consumer thread. The event loop alone owns
socket I/O, TLS keys/records, KeyUpdate and session lifetime; HTTP/2 state and continuations
are shared through the fetch mutex. The consumer drives body/gzip/redirect/harvest work,
while whole Writes are handed to the loop and acknowledged only after socket completion.
Shutdown stops and joins the consumer before freeing fetch or session state. This is not
the established-tunnel record-opening pool or Hysteria's reader/send queue. The current
ownership and backpressure contract is in [CONCURRENCY.md](../CONCURRENCY.md); G2 remains
open, with snapshot-specific tests and paired measurements in [TESTING.md](TESTING.md).

## Diagnostic switches

Environment variables, off unless set. Each one decides on presence alone: the value is never
parsed, so `LC_OPEN_LOG=0` turns the switch on just as `LC_OPEN_LOG=1` does.

| variable | where | what it writes |
|---|---|---|
| `LC_OPEN_LOG` | `lc-tunnel` | The destination host and port on every per-connection line that has one: the connection opened, the connection handed to the kernel (`direct copy engaged`), and the address a dial that gave up was made for. Together that is a list of where people on the LAN went, sitting in the router's syslog (212 distinct addresses in one ring buffer on one router). It is also the largest producer of log lines: 250 of 1112 over 7¼ hours on a live router, 22 % of a ring that is 128 KB by default. With it off, failures are still reported with the stage they reached, without the destination. |
| `LC_QUIC_LOG` | `lc-tunnel`, `lc-hy` | ngtcp2's own account of every QUIC frame sent and received. Very loud. Useful because a QUIC connection that fails says nothing on a socket (no alert, no reset), so otherwise the only symptom is silence. |
| `LC_HY_DUMP` | `lc-hy` | Path to a file the captured Hysteria2 handshake is written to. |
| `LC_PROBE_DUMP` | `lc-probe` | Directory the probe writes its captures into. |

The statistics block is not a variable. `lc-tunnel` prints it on `SIGUSR1`, so how often it appears
is up to whatever sends the signal.

## Dependencies, and why they are shaped this way

**mbedTLS and zlib come from the router.** Every OpenWrt image already carries libmbedtls (crypto,
x509 and tls in one package) and zlib, so linking against them costs NEEDED entries, not flash.
OpenSSL's libcrypto is 6.2 MB. The Mi Router 4A had 2.2 MB free on its overlay when that was
measured on 26 August, and a clean install has 5 360 KB free (the table at the top): it does not
fit either way.

**ngtcp2 and nghttp3 are built from source into the binary.** Both are packaged for `mipsel_24kc` in
the OpenWrt feed, but the feed cannot be used. Measured against 25.12.5 on a Mi Router 4A:

    libngtcp2.so.16.5.0            223 287   needs libc and libgcc_s only
    libnghttp3.so.9.3.0            119 547   needs libc and libgcc_s only
    libngtcp2_crypto_ossl.so.0     29 206    needs libcrypto.so.3 and libssl.so.3

The `libngtcp2` package ships the core library and the OpenSSL crypto backend together and declares
the dependency for both, so `apk add libngtcp2` installs libopenssl3: 4 454 KiB against 5.3 MiB of
free overlay. The core library has no such dependency. The 4.4 MiB is the price of exactly the
backend this project replaces with under 6 KB of its own.

Built into the binary, QUIC and HTTP/3 come to roughly 380 KiB (see the size table in BUILD.md), and
buy loss recovery, congestion control, acknowledgement ranges, flow control and connection
migration, none of which is optional in a QUIC client. Writing HTTP/3 by hand would save about
100 KiB, since Hysteria2 authenticates with one request of four headers, but it would trade flash
the device has for interoperability bugs in a protocol that is hard to observe from a router.

**brotli and zstd decoders are compiled in.** The Firefox fingerprint advertises zlib, brotli and
zstd for certificate compression, and the server may pick any of them (RFC 8879), so the client must
open all three. That costs about 243 KB on mipsel.

**Several trees are references only.** Xray-core, REALITY, uTLS, hysteria, the quic-go fork, qpack,
brotli-go, nghttp2 and the sparse x/net are never linked into the client. They are what the client is
checked against: tests run the Go code on the same inputs, and every `vendor/...:N` citation in a
comment points into them at the pinned revision. Two examples of why they have to be present:
hysteria states its receive window as one number, and the quic-go fork turns it into three transport
parameters (`quic-go/connection.go:329-331`), so reading only hysteria would advertise a third of what
the real client does. And Xray's HTTP/2 is Go's `x/net/http2`, so the SETTINGS a client opens with,
the order it writes headers in, and which HPACK literal form it picks are decided there, not in Xray.

## What the ciphers cost

On an MT7621 the cipher is most of the cost of carrying data. From `build/bench-aead` (source
`test/bench/bench_aead.c`) on that router (MIPS 1004Kc, 880 MHz), 8 MB through each in 16 KB
records, built at the flags the binary ships. Figures count both directions, as a tunnel pays them:

| | this client (2026-09-19) | OpenSSL 3.5.7, same CPU |
|---|---|---|
| AES-128-GCM | 14 Mbit/s (534 ms/MB) | 57.3 Mbit/s |
| AES-256-GCM | 13 Mbit/s (584 ms/MB) | 49.5 Mbit/s |
| ChaCha20-Poly1305 | 87 Mbit/s (91 ms/MB) | 184.7 Mbit/s |

That column is the tree as it stood on 19 September: mbedTLS's AES and ChaCha20-Poly1305, with
BearSSL's GHASH. GHASH and ChaCha20 have been replaced since, as described below.

How GHASH became the question: measured on 26 August, with mbedTLS doing all of GCM, the AES itself
was not the problem. CTR mode is the same key schedule and block function without authentication,
so GCM minus CTR is GHASH, and the subtraction checks itself: GHASH does not depend on key length,
and the two results agree to 1 %.

| 8 MB, 16 KB records | time | rate | GHASH by subtraction |
|---|---|---|---|
| AES-128-CTR (one way) | 751 ms | 85 Mbit/s | |
| AES-256-CTR (one way) | 967 ms | 66 Mbit/s | |
| AES-128-GCM (seal) | 2150 ms | 30 Mbit/s | 1399 ms |
| AES-256-GCM (seal) | 2352 ms | 27 Mbit/s | 1385 ms |
| ChaCha20 (one way) | 294 ms | 217 Mbit/s | |

mbedTLS's portable GHASH was 65 % of the cost of sealing with AES-GCM on this CPU. OpenSSL is faster
because it carries MIPS assembly for AES and GHASH, but linking OpenSSL is the wrong shape for a
router that already has mbedTLS on its flash.

**First replacement, 26 August: BearSSL's GHASH.** mbedTLS's GHASH gave way to BearSSL's
constant-time `br_ghash_ctmul`, with mbedTLS still doing the AES. On the same router, before and
after that change:

| | mbedTLS GHASH | BearSSL `br_ghash_ctmul` |
|---|---|---|
| AES-128-GCM, both directions | 1078 ms/MB, 7 Mbit/s | 343 ms/MB, 23 Mbit/s |
| AES-256-GCM, both directions | 1128 ms/MB, 7 Mbit/s | 365 ms/MB, 21 Mbit/s |
| AES-128-GCM, one way | 14.8 Mbit/s | 36.2 Mbit/s |
| the tunnel, 30 MB through a live server | 10.6 Mbit/s | 17.9 Mbit/s |

The binary grew by 140 bytes. Two things came up on the way. `mbedtls_cipher_update` refuses an
in-place call whose length is not a whole number of blocks, and the record layer seals in place over
records of any length, so the generic cipher layer had to go and `mbedtls_aes_crypt_ctr` is driven
directly. And the in-place case in `test/aead` used 512 bytes, the one length that cannot fail; the
lengths there are now the ones real payloads take.

**Second replacement, 21 September: Go's GHASH.** GHASH is now `src/tls/ghash.c`: the algorithm Go
itself runs on mipsle, where it has no GCM assembly (`crypto/internal/fips140/aes/gcm/ghash.go`, a
4-bit Shoup table with a reduction table), ported line for line. It gives the same answer as
`br_ghash_ctmul` on every input tried, and on the MT7621 GHASH alone takes 88 ms/MB against 172 for
BearSSL's. Like the reference on that architecture, it is not constant-time; `src/tls/ghash.h` says
so, and the maintainer chose it knowing that. ChaCha20 is this project's own now as well
(`src/tls/chacha.c`), and so is Poly1305 on 64-bit machines (`src/tls/poly1305.c`, Go's generic
code). On the MIPS routers Poly1305 stays mbedTLS's: Go's form emulates every 64-bit multiply there,
and took 489 ms per 8 MB against mbedTLS's 62. The tag is the same either way.

**On arm64 both halves of GCM are this client's own**, chosen once at run time the way Go chooses:
Go takes its assembly GCM when the CPU has both AES and PMULL (`gcm_asm.go:34-35`), and uTLS makes
the same test for its cipher preference. With both, as on the AX3000T's Cortex-A53, GHASH
multiplies with PMULL (mbedTLS's own multiply for that instruction set, from `aesce.c`), and since
30 September so is the counter mode: eight blocks at a time through AESE and AESMC, as Go's
`gcm_arm64.s` does, with the key schedule from FIPS-197 (`src/tls/ghash.c`, called from
`src/tls/aead.c`). mbedTLS's `mbedtls_aes_crypt_ctr` does use the AES instructions, but one block at
a time, and it was 5.5 of the 7.0 ms per MB this client spent opening AES-128-GCM, against 1.8 for
the whole of Go's. mbedTLS still encrypts the single blocks GCM needs outside the counter stream
(the hash key once per key, the tag mask once per record), and on the MIPS routers, which have
neither instruction, it does all of the AES.

The bench itself was wrong more than once before these numbers: it compiled the cipher at `-O1`
while the binary ships `-Os` and `-O2`, and its `open` stopped at a failed tag without running the
counter mode. Both are fixed, and the bench now fails loudly if an open fails. Treat any cipher
number in old commit messages with that in mind.

## Known limitations

These are decisions, not a backlog, written down so nobody has to rediscover them from behaviour.

**On the Hysteria2 plane the server's name is resolved once, at startup**, as the hysteria client
resolves it (`fillServerAddr`, vendor/hysteria/app/cmd/client.go:248-258). A DNS change is not seen
until the process restarts. The REALITY plane looks the name up for every dial, as Xray does. On both,
the service exempts the addresses the name has at start from interception; an address it moves to
later is exempted at the next start.

**There is no graceful shutdown.** SIGTERM and SIGINT take the default action: the process stops
where it stands, with connections dropped and nothing flushed.

**The Hysteria2 plane carries every connection on one QUIC connection.** Losing it ends every session
on it. They are closed, and the next request that needs a connection makes a new one: never while
nobody asks, and with no backoff, as the reference's reconnectable client does. At start the first
connection is made before anything listens, and if the server does not answer the process exits, as
the reference does; procd restarts it.

**XTLS-Vision works only on the raw TCP transport.** Over XHTTP the inner TLS records are inside
HTTP/2 frames where the filter cannot see them, so that path is plain VLESS and every byte passes
through this process. Upstream forbids the combination for the same reason.

**Only IPv4 is intercepted.** The service takes TCP ports 80 and 443 (and UDP 443 when asked) from
the listed IPv4 clients. Other ports and all of IPv6 leave the router as they always did. The service
says so in syslog at every start.
