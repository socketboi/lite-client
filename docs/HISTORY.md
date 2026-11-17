# History

This file is the project's history. The repository starts from a clean import, so the roughly 625
commits made between 13 August and 30 September 2026 are not published; what they did, and why, is
summarised here by phase. Dates are commit dates. Numbers are the ones the commits recorded at the
time, on the hardware named next to them. Where a later measurement overturned an earlier one, both
are given and the correction is said out loud, because a fair number of this project's lessons came
from exactly that.

Two routers appear throughout:

- **MT7621** (ramips, mipsel_24kc): a Xiaomi Mi Router 4A Gigabit. 880 MHz MIPS 1004Kc, two
  cores and four hardware threads, 118 MB of RAM, about 7 MB of writable flash, no AES instructions.
  This is the box the project was written for.
- **AX3000T** (mediatek/filogic, aarch64): Cortex-A53 with the ARMv8 crypto extensions, about
  240 MB of RAM.

"The reference" means Xray-core with uTLS and XTLS REALITY for the REALITY plane, and apernet's
hysteria with its quic-go fork for the Hysteria2 plane. The rule the whole codebase follows is that
this client behaves like those, and that any difference is a defect until someone decides otherwise
and writes it down (see [DIVERGENCES.md](../DIVERGENCES.md)).

## 1. Why it exists (13 August)

The routers in question could not run sing-box. On the MT7621 the sing-box package needed about
30 MB of flash and the router had 3.7 MB free. `sing-box-tiny` was 27 MB installed with an RSS near
29 MB. The target set at the start was 1.5 MB of flash and 8 MB
of RSS at most.

The first commit introduced lite-client: a C client for VLESS+REALITY and Hysteria2, built for that
class of router, with transparent-proxy inbound, one outbound and nothing else (no routing engine,
no JSON config; traffic selection stays in nftables and dnsmasq). The binary was 70 KB, and it
carried live traffic on the day it was committed.

The same day brought the first security fix. On the Hysteria2 plane a second Certificate message
could get past the certificate pin, because the "signature verified" flag did not record which
bytes had been verified. The rule adopted then, that every message of a flight may appear at most
once, also stops a second Finished from reinstalling application keys. The UCI config gained the
options (`plane`, `auth`, `obfs`, `rate`, `pin`) without which the Hysteria2 plane could not be
reached from the router's configuration at all.

## 2. First router installs, and making the package fail closed (14 to 15 August)

Putting the package on a real router turned up the class of bug that a household notices first: the
tunnel is gone but the redirection rules are still there. Several paths failed open:

- options were validated only after the interception rules were installed, so a bad pin produced
  endless respawns behind live rules;
- procd does not call `stop_service` once respawn is exhausted, so ports 80 and 443 stayed
  redirected into a dead socket;
- nft rules were added one at a time, so a malformed `clients` entry dropped its own rule while
  earlier ones stayed active with nothing behind them;
- an unreadable obfuscation file quietly turned obfuscation off.

The rule set is now applied atomically with one `nft -f -`, the rule family follows the address,
and every one of these cases was re-run on the router: eight failure cases leave no rules, no table
and no process behind.

The build had its own surprises. A `CFLAGS` from the environment silently dropped `-Werror` and
`_FORTIFY_SOURCE`; the first fix (`override CFLAGS :=`) broke every later `+=` and nothing compiled,
and `make check` did not notice because tests use their own flags. A version stamp from
`git describe` went into the binary after six builds reached the router in one day, and the gate
now builds the same tree twice with different versions to prove the stamp follows. Object files
were made to depend on a flags file, so a change of compiler options rebuilds what it affects.

The Hysteria2 memory model was reworked. Buffers had been allocated at the full stream window on
open, which ran into a limit of 48 connections fourteen times in one browsing session from one PC.
Buffers now grow with the bytes that arrive, the stream cap went to 256, and RSS fell from 1728 KB
to 1092 KB. A free-memory guard was added at the same time; it was removed on 29 September when the
maintainer decided to follow the reference, which has none.

On 15 August the build moved into a Docker image with Go 1.26 pinned by checksum and all Go modules
resolved at image build time, so that `make check` on a clean tree, in a container with no network,
generated every reference vector and passed 466 of 466 checks.

Throughput on the QUIC plane was first addressed here too. The client had offered AES-128-GCM only;
on the MT7621 that costs 1077 ms per MB against 91 for ChaCha20-Poly1305, and Go's own order on a
machine without AES puts ChaCha20 first. The hello now offers three suites in Go's order. The
receive window was 64 KiB, which at 66 ms caps one download near 8 Mbit/s; moving to the
reference's 8,388,608 bytes took a single connection from 6.4 to 26.5 Mbit/s on a 47 Mbit/s line.
Port hopping (modelled on hysteria's `udphop`) and the Gecko obfuscator (checked line by line
against hysteria v2.10.0) were added in the same stretch.

## 3. Three liveness rules, built and then removed (14 to 17 August)

The longest detour of the first week was dead-server detection on the Hysteria2 plane. Servers had
been seen going silent while users waited out a 30 second idle timeout, so the client grew rules of
its own: a shorter keep-alive, a silence threshold, a "three stalled destinations within 30 s"
trigger, a minimum connection lifetime. Each version was measured on the router and each was wrong
in a new way. One never fired (58 stalls, 0 rebuilds in 35 minutes); one fired on healthy
keep-alive connections whose last reply had already arrived; one mistook one-way traffic for
silence and rebuilt the connection 119 times in two hours.

Along the way the pieces around them went back to the reference one by one: keep-alive to hysteria's
10 s (measured on the wire at 10.1 s), UDP session idle to the server's 60 s, and a five-second
half-close waiter, which hysteria does not have, to its two `io.Copy` calls with close on the first
to finish. On 17 August the last invented rule was deleted. The reference rebuilds its connection
only when quic-go reports the connection closed (`reconnectableClientImpl`); a server refusing a
destination is an ordinary failed dial. The client now does the same. The commit that removed it
calls it the fourth version of the same invention, every number in which had been made up, and it
is the reason the project stopped inventing behaviour.

## 4. The first full audit against the references (16 to 18 August)

With the invented rules gone, both planes were read against the reference line by line, and most of
the commits of these days are corrections with a `vendor/...:line` citation attached.

On the QUIC plane the ClientHello went from 7 extensions to 14 in `crypto/tls` order and back down
to 12 when two of them turned out to be sent only with a session cache; supported groups went from
one to five; the two key shares came to reuse one X25519 key as Go does. Transport parameters got
quic-go's GREASE parameter and its order. The Initial grew from 1200 to 1280 bytes (measured with
tcpdump: 1280/1280/1280 for the reference, 1200/1200/1200 for us before the fix). Connection ID
lengths followed quic-go (8 to 20 bytes for the destination, including its modulo bias; 4 for the
source). The client stopped opening the two QPACK streams quic-go never opens, and stopped sending
`SETTINGS_H3_DATAGRAM`, which had made the server hand every Hysteria2 datagram to its HTTP/3 layer
and drop it. With that fix, UDP over Hysteria2 worked against the reference server for the first
time.

On the REALITY plane the audit found that CertificateVerify was hashed into the transcript and never
checked, so any peer could answer with an arbitrary certificate and 64 bytes of noise. REALITY
servers sign with Ed25519, which mbedTLS 3.6 lacks, so a verify-only Ed25519 was written and checked
against RFC 8032 section 7.1. Other findings: the two X25519 shares in the Firefox hello were
generated independently where uTLS reuses one key (invisible to the fingerprint diff, which reduces
key_share to groups and lengths); the client never sent `close_notify`, so every proxied connection
ended in a bare FIN where Xray sends a 24-byte record first; Vision record sizing, long padding and
the 1-second DownlinkOnly timer all differed from `proxy.go`; the GREASE ECH `enc` field held random
bytes where uTLS puts a real X25519 key, so half of all hellos could be told apart by one bit.

Two gates date from these days. `test/fphello` renders the shipped fingerprint table and compares
the hello byte for byte against a frozen uTLS capture, which had previously been a check someone had
to remember to run. And the REALITY "spider" arrived. When the server does not recognise the client
and relays the real site instead, Xray does not hang up: it fetches that site over HTTP/2 on the
same connection, like a browser would. The client did the same from here on (a first version,
rebuilt twice later).

## 5. UDP over Mux, the stranger path, and the first compressed certificates (18 to 20 August)

Xray with the Vision flow does not send UDP as VLESS command 2; it rewrites the request into Mux
addressed to `v1.mux.cool` and wraps each datagram in xudp. The codec was written first and wired
in second, and the live Xray stand caught three errors that reading had not: the flow must stay in
the addons, a Mux request carries no address or port, and `tcp:v1.mux.cool:0` in the server log is
expected. A DNS query then came back through the tunnel with the server's Vision padding on it.

On that same "stranger" path, where the server relays the real site's handshake, Xray verifies the
site's certificate against the system roots and stops with `bad_certificate` if it fails. The
client had done nothing there, so "the server does not know us" and "someone is in the middle" were
the same event. `src/cert/chain.c` now asks
mbedTLS the question Go's x509 asks, with roots searched in Go's order; the cost is a NEEDED entry
and 1,888 bytes of text, since libmbedx509 is already on the router.

The Firefox fingerprint advertises certificate compression with zlib, brotli and zstd. A survey of
seven public sites showed three of them sending brotli-compressed certificates, which the client
could not open. RFC 8879 makes the advertised list a promise, and at the time brotli's dictionary
looked too large for the flash, so the list was trimmed to zlib and a zlib decompressor written.
That trim was the one deliberate difference in the hello for the next two and a half weeks
(section 8 closes it).

The XHTTP transport (VLESS over HTTP/2, exercised by `lc-xfetch` and not wired into the tunnel) got
the same treatment on 19 and 20 August. Its request carried five header fields where Xray sends
eighteen, with no User-Agent at all, which no browser or library does. Xray fills them in with the
same Chrome identity the spider uses, in its "fetch" variant, and so does this client now. SETTINGS,
the connection window and HPACK behaviour were compared against x/net's HTTP/2 client (vendored for
the purpose), and the ordinary headers are now written in a random order per request, because Go
writes them by walking a map. One fix in this group went wrong first: the connection credit was set
to 1 MB from the server branch of x/net's defaults, and was put back to the client's 1 GB the next
day.

A Hysteria2 download test from the router ended after about two seconds every time: the receive
buffer grew towards the 8 MB window, the memory guard refused, and the stream was reset. The window
was cut to 512 KB for the time being. The next day a capture at the server showed the real
throughput problem: the tunnel pumped a stream once per loop turn, and ngtcp2 sends window updates
only when a quarter of the window has been consumed, so the transfer ran in bursts every five
seconds. Draining while the stream had bytes and the client took them, as `io.Copy` does, took the
tunnel from 40 kB/s to about 2 MB/s. Two of the "after" measurements that day were thrown out
first: one ran against an old process still holding the port, the other against a binary that make
had not rebuilt.

## 6. Measuring the reference instead of reading it (25 to 27 August)

A live incident started this phase. A phone joining Wi-Fi opened all its background connections at
once, and at 60 concurrent handshakes each open took about 9.5 seconds. The suspicion fell on the
post-quantum group, and bisection on the router refuted it: ML-KEM-768 cost 3.7 ms, and the whole
gap between a plain TLS 1.3 handshake (86 ms) and a REALITY one (482 ms) was Ed25519 verification at
342.74 ms on generic bignum arithmetic. A dedicated field reduction and Straus's double-scalar
multiplication brought verification to 82.41 ms and the full handshake from 448 to 186 ms on the
MT7621. Skipping the verification, which the REALITY HMAC arguably makes redundant, was rejected
because the reference verifies.

Two older decisions were reversed the same day. On 14 August the client had been given a separate
three-second budget for the TLS handshake after connect; Xray bounds connect and handshake with one
context, and on the MT7621 the work after connect is largely this client's own crypto, queued
behind a browser's fifteen parallel connections. There is now one budget, as in the reference.

The client had also refused the flow `xtls-rprx-vision-udp443` as an obsolete name, while Xray
accepts it today and, without it, refuses UDP to port 443 before building a request. The client
had been sending intercepted QUIC into the tunnel on a configuration where Xray would not have sent a
single packet; it now refuses UDP/443 unless that flow is set.

The more lasting change of the phase was method. On 25 August a quic-go server built from the vendored
fork showed that the hand-built QUIC hello offered twelve signature schemes where the reference
offers seven and omitted `signature_algorithms_cert`: the right constant copied from the wrong
context. A test written from the same reading would have agreed with the bug. So capture tools went
into the tree (`tools/vendorcap/qstand` for QUIC, `vlesstrap` for the VLESS and Vision plaintext),
and from then on formats were frozen from bytes the reference produced rather than from a person's
reading of its source. The same day the client ran end to end through a reference REALITY server
(authenticated, HTTP 200, 868 bytes back), and `vlesstrap` in relay mode observed Xray's long Vision
padding on the wire: 921 = 101 + 900 − 80, the reference formula to the byte.

On the router the REALITY tunnel was CPU-bound in AES-GCM, and specifically in GHASH: 3559 ms per
8 MB, against 68 ms for Poly1305 in the same library, because mbedTLS XORs byte by byte on MIPS. A
constant-time GHASH from BearSSL took the tunnel from 10.6 to 17.9 Mbit/s (a faster table-based
variant was measured and set aside at the time because it is not constant-time). Multi-process
workers with `SO_REUSEPORT` gave 20.5 to 35.3 Mbit/s over four parallel downloads, and a USR1 sent
to the supervisor, which had no handler, took the household offline once before that was fixed.

Twenty-six of the forty handshake failure paths closed the socket where Go sends an alert. They
were fixed, and then `test/seam`, which runs the real binary against a fake server, showed that the
tunnel had never sent a single alert: only a blocking helper the tunnel does not use ever wrote one.
Certificate decompression was verified live for the first time against an OpenSSL 3.5 server that
really compresses (`test/certcomp/live.sh`, part of the gate since).

## 7. Latency, probe resistance and HelloRetryRequest (27 to 30 August)

The hello is now built while the TCP handshake is in flight (21 to 63 ms off time to first byte),
and a pool of pre-opened tunnels, shaped after Xray's pre-connect goroutines, took the median open
from 0.59 s to 0.17 s in a paired test. The pool was later (15 September) reduced to exactly Xray's
`testpre` behaviour, and `check-pool` holds its numbers to the vendored lines. TCP keepalive on
server connections now matches Xray's dialer.

An automated reference-citation audit, which pairs every `vendor/...:line` citation in a comment
with the code it names and has a reviewer judge each pair, became part of the routine here. Most of
its findings were false, and a fair share of the work went into making the pairing itself honest
(ambiguous file names, citations broken across lines, line numbers pointing at blank lines). The
real findings it did produce were mostly active-probe distinguishers: behaviours any party on the
path can trigger without keys and read off the wire.

- a ChangeCipherSpec was accepted by its type byte alone, where uTLS checks the body;
- a first record of type 0x80 drew a FIN where uTLS sends `protocol_version`;
- a first record with version 0xFFFF drew an alert where uTLS drops it silently;
- an unusable server key share drew a FIN where uTLS sends `illegal_parameter`.

HelloRetryRequest support arrived on 30 August, measured against uTLS through a new `fp retry`
subcommand: random and session ID carried over, key_share rewritten to one entry, every byte after
it identical. P-384 and P-521 key exchange came with it, and the gate caught a real stack overflow
in the P-521 path on the first build. The same week the gate started cross-compiling every program
for mipsel, after a green `make check` had turned out to be compatible with a tree that did not
build for the router.

## 8. Upload, untested decisions, certificate compression done (30 August to 5 September)

Hysteria2 upload measured 0.6 Mbit/s against 9.8 down on the MT7621. ngtcp2 keeps a pointer into
the application's buffer until the data is acknowledged, so a flat buffer could neither grow nor
compact while anything was in flight. `src/quic/txbuf.c` became a list of blocks that never move.

Early September was spent on decisions that nothing tested: whether Vision may stop sealing records
and splice (`test/vfilter`), CertificateVerify with real Go signatures (`test/certverify`), the
REALITY key parsers (`test/keys`), the fingerprint table loader, which on a truncated file produced
an all-zero hello rather than an error (`test/fpt`). Port hopping moved to `src/quic/hop.c` with its
own test, and the gate gained a per-suite timeout after a mutant hung it. An ECN bug surfaced: under
Salamander the ECN decision read the first byte of the obfuscated packet, a random salt byte, so half
of the 1-RTT datagrams went out unmarked.

On 5 September certificate compression was finished properly. Measurement showed that even with
zlib listed first, every compressing site answered brotli, and a client that advertises three
algorithms and fails on one is unique on the wire. brotli and zstd decoders were vendored
(decompression only). The cost on mipsel was 243 KB of flash, 122 KB of it brotli's static
dictionary; lc-tunnel went from 660,460 to 929,648 bytes (unstripped, with debug information),
which the 4A's free flash could absorb.
The first build of that change broke every router using the Chrome table (whose list is brotli
only), because the check compared the list for equality; the list is now read as a set and a
capture from a router with the Chrome table sits in `test/fphello`.

## 9. GSO, the 8 MiB window, and the reference client on the same box (6 to 11 September)

The Hysteria2 transmit path learned `UDP_SEGMENT` batching as quic-go uses it; on the MT7621 upload
went from 21.5 to 25.6–28.2 Mbit/s at the same CPU. The profile then showed `ngtcp2_conn_writev_stream`
and `ngtcp2_conn_read_pkt` holding two thirds of the time, so the single-connection ceiling was the
one core that runs the connection. That observation is the root of the multi-core work in September.

On 7 September a comparison against sing-box on the AX3000T turned out to be invalid (sing-box had
been on REALITY, not Hysteria2), and a single download was found to be limited by the per-flow
window rather than CPU: 42 Mbit/s, going to 80 with a 1 MiB window. The cost that grew with the
window was quadratic: `lc_qrx_take` moved the remainder of the receive buffer on every take. With a
read offset instead, the reference's 8 MiB window cost 52% of a core, and the same box ran the
reference hysteria client for comparison:

| AX3000T, one download, Hysteria2 | Mbit/s (five runs) | CPU | RSS |
|---|---|---|---|
| lite-client, 8 MiB window | 93 / 128 / 122 / 109 / 129 | 52% | 2,416 KB |
| hysteria client | 92 / 128 / 115 / 114 / 125 | 69% | 38,664 KB |

The window went back to the reference values for good (8,388,608 per stream, 20,971,520 per
connection), and with that the transport parameters matched quic-go's set, order and values. The
MT7621 went from 17–20 Mbit/s at 84–87% CPU to 27–39 at 57%.

The REALITY plane got Xray's dial retry (`retry.ExponentialBackoff(5, 200)`, which is linear in
practice), stale pooled tunnels were handled as Xray's pool walk handles them, and the gate grew
several checks that read numbers straight out of the vendored reference: `check-retry`, `check-rsa`,
`check-ack`, `check-refs`, `check-fingerprint` and `check-vendor`.

## 10. The stand moves into the tree, and ngtcp2 starts to be patched (12 to 16 September)

`test/hystand/run.sh` builds the reference Hysteria2 server from the vendored tree, puts an echo
target on its loopback and pushes 32 MB through this client, checking every byte by its offset. Its
README carries a control (break the client on purpose, watch the stand fail), because a stand that
cannot fail may well be testing the loopback. The Hysteria2 connection lifecycle was rewritten as the
reference's `reconnectableClientImpl`: connections on demand, no reconnect while idle, a 5 s
handshake idle timeout, an unconnected socket so ICMP does not kill the connection. Each rule has a
scenario on the stand and a mutation that fails it.

On the REALITY plane a new stand, `tools/vendorcap/wireshape`, ran the reference client and this one
against the same Xray server under strace and compared every write toward the server. The write
path was rebuilt to follow Xray's writer chain (one write per record, the 500 ms wait for the
client's first bytes, the lone header on timeout), and close semantics to follow its activity
timer.

The Hysteria2 plane runs on ngtcp2, and ngtcp2 is a correct QUIC implementation that is not quic-go.
The Initial packet is readable by anyone who sees the cleartext connection ID, and timing, ACK
cadence, packet-number lengths, padding placement and congestion control are all visible on the
path. Rewriting QUIC in C to match quic-go was out of proportion; carrying a fork had already
produced one surprise (a fork patch that crumbled the first Initial into uneven CRYPTO frames, which
quic-go does not do). From 15 September ngtcp2 is built as pinned upstream plus a series in
`patches/ngtcp2/`, one behaviour per patch, each header citing the quic-go lines it follows:

| patches | what they make ngtcp2 do as quic-go does |
|---|---|
| 0001–0004 | keep-alive timing, PING in ACK-only packets, ACK timing, PTO and probe counts |
| 0005–0008 | ClientHello layout in the Initial (one cut at the second half of SNI, sent last), packet number length, padding of coalesced datagrams, path MTU discovery |

## 11. Hysteria's own BBR (16 to 19 September)

hysteria does not use quic-go's congestion control. Given no bandwidth, it replaces it with its own
port of Chromium's BBRv1, about 2,600 lines of Go; ngtcp2's BBR is BBRv2, a different state machine.
The maintainer decided to port the reference's controller, and patch 0009 adds it to ngtcp2
(about 1,900 lines: state machine, bandwidth sampler, ACK aggregation, windowed filter, pacer).
`test/hybbr` checks the arithmetic, and a ninth stand, `tools/vendorcap/bbrcmp`, drives the
reference package and the port through the same script: no difference in any of 15 rounds.

Getting there exposed that the client had not been pacing at all. It also exposed a flaw in the
loss stand: its delay was one timer per packet, which reordered packets, so it was a reordering box
rather than a delay line. Every earlier number from that stand was declared void. With a FIFO delay
line, at 1% loss, the two clients overlapped (ours 245 / 343 / 335 Mbit/s, the reference 281 / 347 /
393). The AEAD benchmark was found to be measuring its own test build (99 Mbit/s for AES-128-GCM
where the shipping flags give 175), and a table of throughput figures inherited from it was
corrected across the README and headers.

## 12. Threads, and crypto written for the router (20 to 23 September)

The Hysteria2 plane still packed its datagrams less densely than the reference (86% against 91–93%
on the stand), and REALITY uploads paused for about a millisecond where Xray did not. Both had the
same root: the reference has a goroutine parked in each read, and this client had one event loop.
A reader thread came first (`src/net/reader.c`), with a stop rule set in advance: if density did not
move, no more threads. It did not move, and the thread was not extended to REALITY. A send queue
with a writer thread (`src/quic/sendq.c`) followed quic-go's `send_queue.go` literally.

The density gap was finally found on 21 September after about eight refuted hypotheses: the pacer
was charged twice for every data packet, so since 19 September the client had run at half the
controller's rate. Counters placed in a copy of quic-go showed the reference pacing-limited 19 times
in 3,162 and this client 8,655 times in 10,141. After the fix the clean stand moved 32 MB round
trip in 0.78 s, where it had taken 4 to 9 s.

Handshake cost on the MT7621 went from 134.7 ms of asymmetric work to 30.2 ms. mbedTLS computed
X25519 through its generic ECP code, so the project wrote its own 2^255−19 field (ref10 layout on
32-bit, Go's 5×51-bit representation on 64-bit) and moved Ed25519 onto it. X25519 went from 16.4 to
5.3 ms per multiplication and Ed25519 verification from 82 to 11 ms. Paired live handshakes with
`lc-probe` on the 4A: median 510 to 360 ms.

GHASH was replaced once more, this time with what the reference runs. Go on mipsle uses the generic
4-bit Shoup tables of `ghash.go`, ported line by line (88 against 172 ms per MB for BearSSL on the
MT7621; not constant time, like the reference, which the maintainer accepted). On arm64 Go uses
PMULL when the CPU has AES and PMULL, and so does this client now: AES-128-GCM on the AX3000T went
from 334 to 1,185 Mbit/s one way. That change was prompted by a paired run on the AX3000T in which
REALITY did 121.6 Mbit/s against Xray's 175.8 at three times the CPU per byte. ChaCha20-Poly1305
followed x/crypto (NEON on arm64), and the Salamander salt came to be drawn from a port of Go's
`math/rand`, as hysteria draws it.

REALITY started one worker per CPU by default, like GOMAXPROCS (maximum 8), and a series of commits
brought every TLS alert number and every order of checks on both planes in line with uTLS and Go's
`crypto/tls`. One of them had been wrong since the start: `unsupported_certificate` was 48, which is
`unknown_ca`; the reference's is 43. `check-alerts` now holds every alert constant to
`vendor/utls/alert.go`. Patch 0012 bounded CRYPTO data at quic-go's 16 KiB (`check-crypto`), and
`check-arm64` began running the arm64 crypto paths under qemu.

## 13. REALITY against uTLS, the spider rebuilt, TCP memory on routers (24 September)

A tenth stand, `tools/vendorcap/nodealert`, runs the REALITY server itself with hooks that let it
send any record after the handshake, against both Xray's client and this one, and compares what each
says back. Certificate verdicts, CompressedCertificate parsing (570 cases against uTLS's own
`decompressCert`), the Vision reader (240 streams against Xray's `VisionReader`), KeyUpdate,
post-handshake records and the ALPS reply were all brought in line with it, 50 scenarios of 50.
Vision's splice path now copies as Go's `internal/poll` does.

The spider was the other large piece. An eleventh stand, `spiderredir`, showed that Xray follows
redirects on the same HTTP/2 connection with a dynamic HPACK table, up to ten hops, sends window
updates and opens a second connection preface for a foreign host; this client sent nothing after the
first request in all twelve scenarios. By the end of the day `src/reality/fetch.c` was a model of
x/net's ClientConn and `http.Client.Do`, with Go's gzip reader, HPACK encoder and decoder, URL
parser and redirect policy ported and held to vectors that Go itself produced. The following day
added `idna.Lookup` with Go's own Unicode tables, at a cost of about 116 KB of text on mipsel,
which the maintainer accepted because the reference has it.

On the routers, the kernel's TCP memory turned out to be the ceiling for REALITY. With a per-socket
buffer of 32 MB against 21.6 MB for all of TCP on the AX3000T, the kernel discarded SACKed data and
the server retransmitted 26–41% (the same happens under Xray). The init script now sizes `tcp_mem`
from the kernel's own estimate, capped by half of the free memory at start (`test/tune`). AX3000T
went from 130–150 Mbit/s with stalls of up to 150 s to 183–219, and the MT7621 from 32–35 to 66–69
(HTTPS over REALITY on a 110 ms path).
REALITY workers also started sharing one listener with `EPOLLEXCLUSIVE`, after `SO_REUSEPORT` had
put two downloads on the same worker four times in twenty.

A citation checker, `tools/cites/claims`, went into the gate as part of `check-cites`. It checks that
the code a comment quotes, the function it names and the numbers on the cited line are where the
citation says. Its first run found about 150 drifted line numbers.

## 14. Upgrading both references (25 to 26 September)

On 25 September the Hysteria2 reference moved from hysteria v2.10.0 to app/v2.12.3 on a newer
quic-go. Every citation into the old trees was carried across with `tools/cites/claims -remap`, a
diff-based mapping between two revisions. The new reference parrots Chrome's QUIC stack by default
since 2.11 (uTLS ClientHello, zero-length source connection ID, 1250-byte first datagram), so this
client does the same unless `option chrome_parrot '0'` is set. The Chrome hello is rendered from uTLS
by `tools/fp` into `src/quic/chrome_hello.h` and gated like the Firefox table.

On 26 September Xray moved to v26.9.9, built with Go 1.27, and REALITY to a newer revision. 76
citations moved. The spider followed Go 1.27's `net/http` and Unicode 17 tables. Without the parrot,
key exchange groups now follow Go 1.26's `crypto/tls`, including ML-KEM-1024 hybrids.

The ngtcp2 series grew to 0024 over these two days: Chrome packet layout, connection ID rotation,
receive-window auto-tuning, retransmission order, NewReno until authentication (the reference only
switches to BBR on the auth reply), loss detection, RTT estimation, packet-number skipping, payload
layout and window-update timing. `tools/qgovec` lays small generators into the vendored quic-go
packages with `go test -overlay` and runs them, and `test/ngpatch` replays their scripts on the
patched ngtcp2.

On 26 September `DIVERGENCES.md` was introduced at the maintainer's request: one list of every known
difference from the reference, with a `DIVERGES: <id>` mark at each site in the code and
`check-divergences` failing when a mark and a row disagree. It started with 17 rows. By the evening
of 26 September no unported difference from Xray or hysteria remained on it; what was left was
behaviour of the Go runtime (G rows) and one deliberate deviation (O1, REALITY as one process per
core).

## 15. The second full pass (27 to 29 September)

A second systematic pass over both planes produced findings with IDs (V for VLESS, Q for QUIC, H for
Hysteria, S for the spider, L for lifecycle, T for TLS), each entered in the registry and then
ported:

- the authentication request byte for byte as qpack v0.6.0 encodes it, no ceiling on streams,
  STREAMS_BLOCKED (patch 0025);
- VLESS UDP without a flow as Xray sends it, xudp frames without an address, the response header
  parsed like `proto.Unmarshal`;
- key updates initiated after 100 packets and then every 100,000 (0026), CONNECTION_CLOSE at every
  encryption level during the handshake (0027), handshake confirmation on an ACK of a 1-RTT packet
  (0028), 64 ACK ranges (0029), ECN as quic-go's `ecnTracker` (0030), ACK processing over quic-go's
  history (0031), PTO probes (0032);
- UDP replies that wait on EAGAIN instead of being dropped (`test/udpwait`), and a stream the server
  ends early handled as `ClosedError` (`test/hystand/closed.sh`);
- the REALITY server name resolved on every dial the way Go's `net.Dialer` does it
  (`test/dialname`);
- transport errors closed with quic-go's codes and words (0033, `check-qgo-reasons`), and
  certificate parse failures under the Chrome parrot with the words of Go 1.26.6's
  `x509.ParseCertificate`, ported as `src/cert/x509go.c` and checked against 19,429 answers Go gave
  on amd64 and 386.

The first batch of this pass broke the second connection through the tunnel while `make check` stayed
green; the stand's twenty short connections caught it, and `test/qslot` now asks the same question
without a server. Two items were decisions rather than ports: TLS 1.2 support on the REALITY plane
as uTLS has it (T3, 34 handshakes against Go's server in `test/tls12`), and removal of the memory
guard entirely, as in the reference (L1).

## 16. Using every core (29 to 30 September)

With the protocol side at parity, the remaining gap on small routers was that one connection runs
on one core. The reference spreads work through Go's scheduler; this client cannot do that without
changing what it puts on the wire. Two deviations were approved by the maintainer and recorded as
O2 and O3, with the rule that the wire stays the reference's:

- **O2, Hysteria2 receive on all cores.** The loop reads a batch of up to 32 datagrams; opener
  threads (one per core minus one, at most seven) remove Salamander, header protection and AEAD on
  copies of the 1-RTT keys; ngtcp2's callbacks take the precomputed answer only when every input
  matches, and compute it themselves otherwise. Patch 0034 exposes the keys; `test/rxopen` checks
  the callbacks against their own computation. On the LAN stand the MT7621 went from 47 to 75 Mbit/s
  and the AX3000T from 208 to 287, where the reference client does 218.
- **O3, REALITY records on all cores.** Whole records already read (up to 16) are opened by threads
  with their own copy of the key, and the loop takes an answer only when record, length, sequence
  number, key, IV and capacity all match. `test/recopen` covers it. Through a live server, one
  download on the MT7621 went from 27.6 to 51.4 Mbit/s.

On 30 September the client first modelled how uTLS reads the server's socket (`bytes.Buffer`
growth and Go 1.27's allocator size classes, `src/tls/rawin.c`), so that it asked the kernel for
exactly what the reference asks for. `tools/rawin` ran 440 streams through the real code and
`test/rawin` holds the model to all 111,369 reads. This closed the last `nodealert` scenario: on a
huge record the reference had read 576 bytes and got a RST, while this client had read further and
got a FIN. But a read of the reference's size brings two or three records, and threads can only
open what a read has brought: O3's gain on the MT7621 shrank to 27 to 37 Mbit/s through a live
server, and to 45–49 Mbit/s on the LAN stand.

The same day the maintainer allowed reading ahead again, provided nothing on the wire changes. On
an open tunnel the socket is read up to four records at a time, and the model of uTLS's `rawInput`
runs alongside it, counting what the reference would not yet have read. The one place that shows on
the wire is a close with such bytes pending: the reference closes with them unread in its socket,
which the kernel answers with a RST, so the client closes that connection with a RST too
(`SO_LINGER` 0). The handshake, spare tunnels, the spider and a single-core router still read in
the reference's sizes. `nodealert` gained a 52nd scenario, `hugeahead`, which sends the huge record
once the client is already reading ahead, and `wireshape` a tunnel whose reads of the server are
slowed down so that the announcement of direct copy and the raw bytes after it arrive in one read.
On the MT7621 LAN stand (the reference Xray server, 100 MB over plain HTTP, one connection) this
gives 57–59 Mbit/s, back where O3 was before its reads were limited. The live server was not
measured with this build.

The last three rows of the register that were not the maintainer's decisions closed the same day.
Q7: a failure of the client's own (memory, keys, randomness) now ends the connection silently, as
the reference process does when it dies, instead of closing with an alert or a CONNECTION_CLOSE.
G7: a server given by name is resolved by a port of Go's own resolver (`src/net/goresolve.c`),
queries, retries, caches and RFC 6724 order included, where musl's `getaddrinfo` had stood in.
G4: the certificate chain a REALITY client verifies when the server did not authenticate it is now
go1.27.1's own `Certificate.Verify` — its parser, path building, hostname rules, EKU nesting,
policy graph, name constraints, signature checks (ML-DSA included) and system store —
in `src/cert`, where mbedTLS had answered a similar but different question. It is held to Go by
re-making every `Verify` call of Go's own crypto/x509 tests plus a generator of chains aimed at
what those tests leave alone (`test/goverify`, about 11,000 calls), and libmbedx509 is no longer
linked. The handshake's own signatures (CertificateVerify, and a TLS 1.2 ServerKeyExchange)
went the same way: mbedTLS accepted an ECDSA signature re-encoded with a needless zero or a long-form
length, which Go refuses, and the Ed25519 verifier refused keys Go takes (a y at or above p, a zero x
with its sign bit set); both planes now judge them with the same Go ports.

## Where things stand on 30 September

**Size.** The first binary was 70 KB. When the package was built with the SDK on 10 September, its
stripped `lc-tunnel` was 366,387 bytes without the Hysteria2 plane and 786,811 with it (the two
planes ship as separate packages). The binary has roughly doubled since: the stripped mipsel cross
builds of the current tree are 724,848 and 1,317,780 bytes (see "Sizes" in
[BUILD.md](BUILD.md#sizes)). Among what came after are the IDNA port (about 116 KB of text), the
port of Go's x509 parser, TLS 1.2 and the threads of O2 and O3. The largest single costs over the
period were hardening (PIE and full RELRO took the mipsel binary from 411,732 to 595,100 bytes on
16 August) and the brotli and zstd decoders (243 KB). The router's libmbedcrypto and zlib are used rather than
shipped.

**Memory.** RSS on a live router was 2,296 KB after a 14.5-hour soak on 20 September (366 tunnels,
1.9 GB carried, no restarts). On the AX3000T with the reference's 8 MiB windows it was 2,416 KB,
against 38,664 KB for the hysteria client.

**Throughput**, as last measured:

| plane, box, setting | lite-client | reference client |
|---|---|---|
| Hysteria2, AX3000T, LAN stand, O2 | 287 Mbit/s, 4.32 CPU-s per 100 MB | 218 Mbit/s, 4.83 CPU-s |
| Hysteria2, MT7621, LAN stand, O2 | 75 Mbit/s | (not recorded) |
| Hysteria2, AX3000T, live server, one download (7 Sep) | 93–129 Mbit/s at 52% CPU | 92–128 Mbit/s at 69% CPU |
| Hysteria2, loss stand, 1% loss, 25 ms (26 Sep) | 229 / 337 / 271 Mbit/s | 237 / 354 / 313 Mbit/s |
| REALITY, MT7621, LAN stand, one download over plain HTTP, O3 reading ahead | 57–59 Mbit/s (33 before O3, 45–49 with the reference's reads) | (not recorded) |
| REALITY, MT7621, live server, one download, O3 with the reference's reads | 37 Mbit/s (27 before O3) | (not recorded) |
| REALITY, AX3000T, after `tcp_mem` sizing | 183–219 Mbit/s (130–150 before) | (not recorded) |
| REALITY handshake crypto, MT7621 | 30.2 ms (134.7 on 20 Sep) | (not recorded) |

"Not recorded" means the commits did not record a same-box figure for the reference client. The
README's performance table and `CONCURRENCY.md` carry the side-by-side runs made since.

**Tests.** The gate went from 426 checks on 14 August to 2,057 on 26 September, the last count a
commit recorded, plus the device builds for mipsel and aarch64 and the arm64 crypto run under qemu.
[TESTING.md](TESTING.md) describes all of it.

**Differences from the reference.** `DIVERGENCES.md` lists one item still being worked on (Q7: the
CONNECTION_CLOSE reason when the client itself fails, for example on memory, under the Chrome
parrot, which the reference cannot produce because Go crashes instead), seven items that are
behaviour of the Go runtime rather than of the reference's code (G1 to G7), and the three deliberate
deviations O1 to O3.
