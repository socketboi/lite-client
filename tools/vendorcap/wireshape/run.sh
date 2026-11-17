#!/bin/sh
# The seventh stand: what the REFERENCE CLIENT and this one write towards the node, write by write.
#
# Every other stand here pins a format. This one pins a SHAPE — how many write(2) calls a connection
# makes towards the node, how large each is and when it leaves — because that is what a path sees
# without decrypting anything, and it is decided by the reference's writer chain (VisionWriter,
# BufferedWriter, tls.Conn.Write, one conn.Write per record) and its readers (dokodemo's socket,
# ReadVReader, the UDP inbound's pipe) rather than by any byte format a test can freeze.
#
# Both clients run against the same vendored Xray REALITY server, each under strace, and each is
# driven through the same scenarios:
#
#   tcp       the client speaks at once              — the request and its first bytes, one write
#   tcpslow   the client says nothing for 1.2 s      — the request's 500 ms wait, then the header alone
#   udp       one datagram                           — the header and the datagram, one write
#   burst     six datagrams during the handshake     — all six with the header
#   tcpbig    300 KB of plaintext at once            — ReadVReader's 1, 2, 4, 8 buffers and reshaping
#   tlsbig    300 KB inside TLS                      — the same with direct copy upstream
#
# Run from the repository root, in the build image (it has Go; strace is installed on the way):
#
#   docker run --rm -v "$PWD:/repo" lc-build:local sh /repo/tools/vendorcap/wireshape/run.sh
#
# after `make build/lc-tunnel`. It prints, per client and scenario, the size of every write to the
# node's port in order, and a count.
#
# ⚠️ WHAT TO READ AND WHAT NOT TO. Sizes vary run to run by the padding draw and by what the kernel had
# queued when a reader looked — compare the STRUCTURE: how many writes, which are ~1208/2394/3580 (the
# record ramp), which carry a frame, where 4118 (a reshaped half) or 8214 (a whole buffer) begins, and
# the last: a 24-byte close_notify one timer after the node's end (see CONNECTION_IDLE_MS in lc-tunnel).
# The trace also records shutdown and close, so a FIN passed on early shows up as a shutdown line.
#
# ⚠️ READ TWO RUNS BEFORE CALLING ANYTHING A DIFFERENCE, because the write COUNT is not stable —
# not here and not in the reference. Two consecutive runs on 2026-09-19, same tree, same image:
#
#   run 1    ref-burst 3 writes: 1887 64 1019          lc-burst 4 writes: 1887 64 1208 336
#   run 2    ref-burst 4 writes: 1887 64 1208 172      lc-burst 3 writes: 1887 64 1196
#
# The two swapped places. Whether six queued datagrams leave in one write or two depends on how many
# had accumulated when the flush looked, which is a race with the scheduler and not a property of
# either client; ref-udp6000 moved between four and five writes the same way. The sizes jitter too,
# for a different and duller reason: Vision's padding draws a random length, so 134 against 180 in
# the same slot is a die roll. WHAT IS STABLE, and therefore what this stand actually pins: the first
# two writes (1887, then 64), the 66-byte lone header in tcpslow, the final 24-byte close_notify, and
# udp443 carrying nothing between the header and that close.
#
# WHEN the writes left, added 2026-09-19, and it found something nobody had looked for. The trace has
# carried timestamps since the first version (-tt); only the sizes were ever read. The gap line now
# reports the same buckets the Hysteria2 stand uses, plus WHICH gaps went over a millisecond, because
# a count alone says nothing about where.
#
# ⚠️ NOTHING here is back-to-back: neither client has a single gap under 100 microseconds, on any
# scenario. The discriminating bucket on this stand is a millisecond, and the worst gap is almost
# always one of the scenario's own deliberate waits — the 1.2 s silence in tcpslow, the 1 s close
# timer at the end — so read the POSITIONS, not the worst.
#
# AND WHAT THE POSITIONS SAY, identical across two runs:
#
#   ref-tcpbig   over 1ms at 1:86ms  2:1.0  3:1.0                    49:2001ms   (91-93 % under 1ms)
#   lc-tcpbig    over 1ms at 1:483ms 7:1.3 11:1.3 16:1.1 21:1.1 26:1.1 33:1.0 46:2003ms   (82 %)
#
# Discounting the first gap (the handshake) and the last (the close timer), the reference pauses twice
# at the start of a 300 KB upload and then not once; this client pauses for about 1.1 ms every five
# writes, the whole way through.
#
# ⛔ WHICH DOES NOT REPRODUCE, 2026-09-21. Once this stand stopped leaving each run's processes alive
# (see the kill below), the same 19 September build measured 95 · 93 · 91 % against the
# reference's 93 %, and today's builds 91-95 % against 91-95 %. An odd gap of ~1.0 ms at write 7 or 11
# turns up in some runs of either client. The two paragraphs below explain a pause that a clean stand
# does not show; they stay as the reasoning about the gate, which is still correct about the reference.
#
# ⚠️ THE FIRST EXPLANATION WRITTEN HERE WAS "the shape of a TIMER being waited on", and the trace
# disproved it within the hour. Tracing epoll_wait as well as the writes shows the gap whole:
#
#     write(11<TCP:…:14470>, 8214) = 8214        the write is accepted in full
#     epoll_wait(4, […], 64, 1000) = 2           returns after 1.0 ms with two fds ready
#     write(11<TCP:…:14470>, 8214) = 8214
#
# The timeout passed to epoll_wait is 1000 ms and it returned in one, so nothing expired: the loop was
# waiting for the CLIENT to have more to give. That is this client's own gate, and it is in
# session_rearm — on this plane the LAN read is armed only while `s->up_n == 0u`, so the next chunk is
# not taken until the previous write to the node has left. The reference has no such gate: dokodemo's
# DispatchLink hands the outbound the inbound's reader, and a goroutine is sitting in read() the whole
# time, so the moment the client writes, the bytes are already taken.
#
# So it is the same root as the density gap on the Hysteria2 plane — one loop alternating where the
# reference reads and writes at once — and the scenario that does NOT show it says the same: tlsbig,
# where Vision hands the connection to direct copy and the gate is out of the path, has a clean middle
# (75-76 of 80 gaps under a millisecond, better than the reference's 70).
#
# ⚠️ AND THE OBVIOUS FIX IS RULED OUT BY THE REFERENCE ITSELF, which is why this gets a paragraph
# rather than a TODO. `up_n == 0` looks like a throttle worth relaxing — let a second read start
# while the first is still being written, and the pause disappears. It is not a throttle. `up_n` is
# the number of buffers in the MultiBuffer being processed, and it is there because Xray's copy loop
# is strictly one at a time:
#
#     for {
#         buffer, err := reader.ReadMultiBuffer()
#         ...
#         writer.WriteMultiBuffer(buffer)
#     }
#                            (vendor/Xray-core/common/buf/copy.go:91-107)
#
# The reference never has two reads in flight either. Relaxing the gate would not close a gap with
# the reference — it would OPEN one, and buy latency with the one thing this client is not allowed to
# spend. What the reference has and this loop does not is a goroutine sitting in ReadMultiBuffer, so
# its alternation costs nothing while ours costs a trip through epoll. Same root as the density gap
# on the Hysteria2 plane, same answer: it is the concurrency, not a constant.
#
# (For the record, since it was worked out before the reference was read: two worst-case reads would
# need 19 412 bytes against UP_QUEUE_SIZE's 18 693, so the queue would also have had to grow by 719
# bytes a session. That is the cost of a change that should not be made anyway.)
#
# AND SINCE 2026-09-20 THE STAND ALSO RECEIVES, which it never did before. Every scenario above
# sends: `big` posts 300 KB and reads one line back. On the live router this client moved 1.86 GB
# down against 51 MB up in fourteen hours, so the direction that carries the traffic had never once
# been compared with the reference. `tcpdown` and `tlsdown` are `big` turned around.
#
# ⚠️ Read the WRITES for the upload scenarios and the READS for these: a download's writes towards
# the node are a request and then acknowledgements, and their sizes say nothing. What the first run
# of them found, tracing reads as well (300 KB, plain HTTP inside):
#
#   ref-tcpdown   29 reads from the node, average 10 549 bytes, largest 16 570
#   lc-tcpdown   118 reads from the node, average  2 594 bytes, largest  8 209
#
# Four times the syscalls, and a ceiling at one record. The writes towards the client were the same
# shape for both (48 × 6 252 against 51 × 5 886), so it was the taking and not the giving — and the
# cause was in this tree rather than in the protocol: the node's side was read `rx_want` bytes at a
# time, five for a header and then exactly the body, so a read could neither span two records nor
# finish one. It now reads a bufferful and parses the records out of it, which is what the reference
# does and what spider_read in the same file always did (see records_ready in cmd/lc-tunnel/main.c):
#
#   lc-tcpdown    34 reads from the node, average  9 011 bytes, largest 16 645
#
# Nothing of this is visible on the wire — the records are the node's and the plaintext handed to
# the client is unchanged — so it is a syscall count, not a shape. It is written down here because
# this stand is what found it and what will notice if it comes back.
#
# ⚠️ AND IT BOUGHT NO PROCESSOR, measured on the AX3000T against the node the household uses, 50 MB
# each way of the comparison: 0.48 % of a core per Mbit/s before the change and 0.48 % after, over
# three runs at 78-119 Mbit/s. Three and a half times fewer reads and the cost did not move, which
# says what the cost is made of — the same measurement puts the reference at 0.21 %, and the
# difference is AES-GCM's GHASH (see the ceiling table in src/tls/aead.h), not syscalls. Do this
# change for the shape it matches; do not expect speed from it.
#
# ⚠️ `lc-tlsdown` traces no reads at all, and that is Vision doing its job rather than a gap in the
# stand: with TLS inside, the connection is handed to direct copy and the bytes move through a pipe
# with splice, never through this process. The reference, which does not splice on this path, shows
# 30 reads averaging 10 918.
#
# ⚠️ THREE MORE TRAPS, each of which cost a run:
#
#   - THE REFERENCE'S FIRST CONNECTION ON A FRESH SERVER USUALLY FAILS ("nothing back"), on this stand
#     and with either client. It is warmed up here with one throwaway request per client before the
#     scenarios run; without that the first scenario reads as a client fault.
#   - DO NOT READ THE OUTBOUND'S SOURCE FOR THE TIMEOUT PATH. outbound.go shows an empty padded frame
#     after 500 ms; the reference sends the header alone, because the dispatcher's
#     TimeoutWrapperReader times out with `nil, nil` rather than ErrReadTimeout. This stand is how that
#     was found — see request_write.
#   - A PIPE BETWEEN INBOUND AND OUTBOUND IS NOT PART OF THIS PATH. dokodemo uses DispatchLink, which
#     hands the outbound the inbound's own reader, so the per-architecture pipe limit
#     (features/policy/policy.go) changes nothing here: a build with mipsle's limit pinned wrote the
#     same shapes as the amd64 default.
set -u
LC=$(cd "$(dirname "$0")/../../.." && pwd)   # the repository root, wherever it is mounted
HERE=$LC/tools/vendorcap/wireshape
W=/tmp/wireshape; rm -rf $W; mkdir -p $W; cd $W
say() { printf '\n== %s\n' "$*"; }

# ASKED FOR BEFORE IT IS INSTALLED, which is not the order this had. It went straight to apt-get,
# and apt-get needs a network the build image does not always have — so on a machine where strace was
# already sitting in /usr/bin the stand refused to run at all, with "NO STRACE" as its whole account
# of why. The install is the fallback, not the first move.
command -v strace >/dev/null 2>&1 ||
	(apt-get update && apt-get install -y strace) >/dev/null 2>&1 ||
	{ echo "NO STRACE: not installed and apt-get could not fetch it (no network in the image?)"; exit 1; }
(cd $LC/vendor/Xray-core && go build -o $W/xray ./main) > $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
for p in target probe; do
    (cd $HERE/$p && go build -o $W/$p.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
done
gcc -shared -fPIC -O2 -o $W/slowread.so $HERE/slowread.c -ldl >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
# `-e LC_TUNNEL=/repo/…` runs another build — a mutant — as nodealert's does.
TUN=${LC_TUNNEL:-$LC/build/lc-tunnel}
[ -x "$TUN" ] || { echo "NO $TUN: make build/lc-tunnel first"; exit 1; }
cp "$TUN" $W/lc-tunnel

keys=$($W/xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
pub=$(printf '%s\n' "$keys" | awk -F': *' '/Password|Public/{print $2; exit}')
UUID=00000000-0000-4000-8000-000000000001

# THE SERVER'S TARGET IS THE STAND'S OWN TLS 1.3 LISTENER, NOT THE REAL SITE. A REALITY server dials
# its target for every handshake it is handed, so with `www.avito.ru:443` here every run made a few
# dozen connections to a site on the internet — and by 2026-09-21 that site was answering this
# address with 429. Local, the handshake takes 1.5 ms instead of 80, and the stand no longer depends
# on anyone else's rate limit. What it measures is what a client WRITES towards the node, and the
# target changes none of that: the ClientHello is the client's, and the server answers an
# authenticated client with its own key whatever the target is. The name the clients send stays
# www.avito.ru.
#
# ⚠️ IT DID NOT CURE THE RESETS it was first blamed for, because they were not the site's: see the
# note on the kill at the end of the scenarios.
# Private destinations are refused by freedom unless allowed — see the sixth stand.
cat > $W/server.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":14470,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:18443","serverNames":["www.avito.ru"],"privateKey":"$priv","shortIds":["0123abcd"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
cat > $W/client.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[
  {"listen":"127.0.0.1","port":19980,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18080,"network":"tcp"}},
  {"listen":"127.0.0.1","port":19981,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18443,"network":"tcp"}},
  {"listen":"127.0.0.1","port":15400,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":15353,"network":"udp"}},
  {"listen":"127.0.0.1","port":15401,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":443,"network":"udp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":14470,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.avito.ru","fingerprint":"firefox","publicKey":"$pub","password":"$pub","shortId":"0123abcd"}}}]}
JSON

$W/target.bin > $W/target.log 2>&1 &
$W/xray run -c $W/server.json > $W/server.log 2>&1 &
sleep 2
TRACE="strace -f -tt -yy -s 0 -e trace=write,writev,sendto,sendmsg,shutdown,close,setsockopt"
$TRACE -o $W/ref.strace $W/xray run -c $W/client.json > $W/client.log 2>&1 &
$TRACE -o $W/lc.strace $W/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
    $UUID 19971 -t 127.0.0.1:18080 -u 15300@127.0.0.1:15353 -f xtls-rprx-vision -w 1 > $W/tun.log 2>&1 &
$TRACE -o $W/lc2.strace $W/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
    $UUID 19972 -t 127.0.0.1:18443 -f xtls-rprx-vision -w 1 > $W/tun2.log 2>&1 &
$TRACE -o $W/lc3.strace $W/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
    $UUID 19973 -t 127.0.0.1:18080 -u 15301@127.0.0.1:443 -f xtls-rprx-vision -w 1 > $W/tun3.log 2>&1 &
# A FOURTH, WHOSE READS OF THE NODE WAIT 20 ms EACH — see slowread.c: the record announcing direct copy
# and the raw bytes behind it then come in one read, which on loopback they otherwise never do.
$TRACE -E LD_PRELOAD=$W/slowread.so -E SLOWREAD_PORT=14470 -o $W/lc4.strace $W/lc-tunnel \
    $LC/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
    $UUID 19974 -t 127.0.0.1:18443 -f xtls-rprx-vision -w 1 > $W/tun4.log 2>&1 &
sleep 3

for warm in 19980 19971; do $W/probe.bin tcp 127.0.0.1:$warm > /dev/null; done
sleep 6
: > $W/marks
mark() { echo "MARK $1 $(date +%H:%M:%S.%N | cut -c1-15)" >> $W/marks; }
{
for who in ref:19980:15400:19981:15401 lc:19971:15300:19972:15301; do
    n=$(echo $who | cut -d: -f1); tp=$(echo $who | cut -d: -f2)
    up=$(echo $who | cut -d: -f3); sp=$(echo $who | cut -d: -f4); u4=$(echo $who | cut -d: -f5)
    mark "$n-tcp";     echo "$n tcp:     $($W/probe.bin tcp 127.0.0.1:$tp)"; sleep 3
    mark "$n-tcpslow"; echo "$n tcpslow: $($W/probe.bin tcpslow 127.0.0.1:$tp)"; sleep 3
    mark "$n-udp";     echo "$n udp:     $($W/probe.bin udp 127.0.0.1:$up 1)"; sleep 2
    mark "$n-burst";   echo "$n burst:   $($W/probe.bin udpburst 127.0.0.1:$up 6)"; sleep 2
    mark "$n-udp6000"; echo "$n udp6000: $($W/probe.bin udpsize 127.0.0.1:$up 6000)"; sleep 2
    mark "$n-udp443";  echo "$n udp443:  $($W/probe.bin udp 127.0.0.1:$u4 1)"; sleep 2
    mark "$n-tcpbig";  echo "$n tcpbig:  $($W/probe.bin tcpbig 127.0.0.1:$tp)"; sleep 3
    mark "$n-tlsbig";  echo "$n tlsbig:  $($W/probe.bin tlsbig 127.0.0.1:$sp)"; sleep 3
    # AND THE SAME SIZE COMING BACK. Every scenario above sends; this one receives, which on a live
    # router is 97 % of what the client does — 1.86 GB down against 51 MB up in fourteen hours. The
    # writes reported for these two are therefore the small ones (a request, then acknowledgements),
    # and what is worth reading here is the gap line and the reads.
    mark "$n-tcpdown"; echo "$n tcpdown: $($W/probe.bin tcpdown 127.0.0.1:$tp)"; sleep 3
    mark "$n-tlsdown"; echo "$n tlsdown: $($W/probe.bin tlsdown 127.0.0.1:$sp)"; sleep 3
done
# And TLS downloads through the fourth: direct copy with bytes read ahead of the reference behind
# the announcement. Two, because a fresh process reads in the reference's sizes until a read has
# brought two records — the threads that open records ahead start then — and the announcement comes
# a few kilobytes in; the second download finds the process reading ahead from its first byte. Named
# lc4 so that the write shapes above stay lc's.
mark "lc4-tlsdown"; echo "lc4 tlsdown: $($W/probe.bin tlsdown 127.0.0.1:19974)"; sleep 3
mark "lc4-tlsdown2"; echo "lc4 tlsdown: $($W/probe.bin tlsdown 127.0.0.1:19974)"; sleep 3
} | tee $W/results
mark end
sleep 1
# EVERY PROCESS THIS STAND STARTED, the server and the target included — and by what they ARE, not
# by job number. This line used to read `kill %3 %4 %5 %6`, and it killed nothing: the stand runs
# under sh without job control, where a job spec is refused, and the refusal went to /dev/null. The
# processes lived until the container did, which is harmless once per container and poisonous twice.
# Our tunnels could not bind their ports again, so the next run's probes were answered by the FIRST
# run's clients (its binary, its keys), and the next run's traces had nothing in them. And Xray
# listens with SO_REUSEPORT (vendor/Xray-core/transport/internet/sockopt_linux.go:242), so the next
# server bound 14470 BESIDE the old one and the kernel dealt connections between them; the old one
# holds the previous key and refused whatever it was dealt — traced on 2026-09-21: 11 of 17, and the
# hellos it refused open cleanly under the new key. Both clients retried their way through, and what
# leaked out was "connection reset by peer" on a scenario or two, for either client, which a day of
# runs read as the stand's weather. The first run in a fresh container never had one.
#
# Everything this stand starts runs from $W, so that is what is stopped; the strace wrappers end with
# their tracees, and `wait` lets the traces be written out before they are read below.
for p in /proc/[0-9]*; do
    case "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" in
        "$W"/*) kill "${p#/proc/}" 2>/dev/null ;;
    esac
done
wait
sleep 1

for n in ref lc lc2 lc3; do
    grep -E '14470\]>' $W/$n.strace | grep -E 'write|sendto|sendmsg' \
      | sed -E 's/^([0-9]+) +([0-9:.]+) +(write|writev|sendto|sendmsg)\(([0-9]+)<TCP:\[[0-9.:]+->127\.0\.0\.1:14470\]>.* = ([0-9-]+).*/\2 \5/'
done | sort | awk -v marks="$W/marks" '
    BEGIN { while ((getline l < marks) > 0) { split(l, f, " "); nm++; name[nm] = f[2]; at[nm] = f[3] } }
    function secs(t) { split(t, p, ":"); return p[1] * 3600 + p[2] * 60 + p[3] }
    { sc = ""; for (i = 1; i <= nm; i++) if ($1 >= at[i]) sc = name[i]
      if (sc == "" || sc == "end") next
      if (!(sc in cnt)) order[++no] = sc
      cnt[sc]++; sizes[sc] = sizes[sc] " " $2
      # WHEN each write left, not only how large it was. The trace already carries it (-tt), and this
      # is the half of "writes like the reference" that a list of sizes cannot answer: a path sees the
      # gaps. Counted rather than sorted, so no awk needs asort, and in the same buckets the Hysteria2
      # stand uses (test/hystand/impair) so the two planes can be read side by side.
      t = secs($1)
      if (sc in last) { g = (t - last[sc]) * 1000000
                        gn[sc]++
                        if (g < 100) g100[sc]++
                        if (g < 1000) g1k[sc]++
                        else slow[sc] = slow[sc] sprintf(" %d:%.1fms", gn[sc], g / 1000)
                        if (g > gmax[sc]) gmax[sc] = g }
      last[sc] = t }
    END { for (i = 1; i <= no; i++) {
              s = order[i]
              printf "%-12s %3d writes:%s\n", s, cnt[s], sizes[s]
              if (gn[s] > 0)
                  printf "%-12s     gaps: %d, <100us %d (%d%%), <1ms %d (%d%%), over 1ms at%s\n",
                         "", gn[s], g100[s] + 0, (g100[s] + 0) * 100 / gn[s],
                         g1k[s] + 0, (g1k[s] + 0) * 100 / gn[s],
                         (slow[s] == "" ? " none" : slow[s]) } }'
say "server"; grep -v Warning $W/server.log | tail -3

# THE VERDICT, because the lines above are read by eye and a short download reads like a good one.
# From 2026-09-20 to 2026-09-21 this client lost the end of most TLS-inside downloads —
# "lc tlsdown: down 4096 bytes" where the reference had 300120 — and the stand printed it and exited 0
# for a day, because nothing compared the number with what was sent. The four scenarios that move
# 300 KB are checked here for BOTH clients; the exit status is the client's alone.
#
# A "connection reset by peer" on a dial is not expected on a stand that starts clean; see the note
# on the kill above for the one way it was ever made to happen.
say "verdict"
bad=0
for n in ref lc lc4; do
    miss=$(awk -v n="$n" '$1 == n { s = $2; sub(":", "", s)
               if (s == "tcpbig" || s == "tlsbig") ok = $0 ~ /body=300000$/
               else if (s == "tcpdown" || s == "tlsdown") ok = $0 ~ /down 300120 bytes$/
               else ok = 1
               if (!ok) printf " %s%s", s, ($0 ~ /reset by peer/ ? "(reset)" : "(SHORT)") }' $W/results)
    echo "$n:${miss:- all four delivered in full}"
    [ "$n" != ref ] && [ -n "$miss" ] && bad=1
done
# AND EVERY CONNECTION TO THE NODE CLOSED AS THE REFERENCE CLOSES IT. This client reads the node's
# socket ahead of the reference on an open tunnel and closes with a reset — SO_LINGER {1, 0} — when
# the reference would have left bytes in its socket (O3, node_read_ahead in lc-tunnel). Nothing here
# leaves any: every download is read to its end, and after the announcement of direct copy the
# reference reads raw what was read ahead — lc4 reads that announcement together with raw bytes
# behind it. A linger here is a reset where the reference sends a FIN.
lingers=$(cat $W/lc.strace $W/lc2.strace $W/lc3.strace $W/lc4.strace | grep -c 'setsockopt(.*14470.*SO_LINGER')
echo "lc: $lingers connections to the node closed with a reset"
[ "$lingers" -eq 0 ] || bad=1
exit $bad
