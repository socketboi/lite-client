#!/bin/sh
# The tenth stand (spiderlife is the eighth, bbrcmp the ninth): what the REFERENCE CLIENT and this
# one say back when the node's side of the TLS stream goes wrong after the handshake.
#
# Once a REALITY connection is up, the reference reads the node through uTLS's readRecordOrCCS
# (vendor/utls/conn.go:612-791) and UConn's handlePostHandshakeMessage
# (vendor/utls/u_conn.go:957-984). Every refusal there sends
# an alert, and the outbound then closes, which adds close_notify. Several of those refusals answer
# bytes anybody on the path can write — a record header, a record that does not open, a
# ChangeCipherSpec, which is never encrypted — so what the client says back is visible without a
# key. The rest need the node's key, and a stock node does not produce them; they are here because
# a divergence is a divergence (see node_record in src/cmd/lc-tunnel/main.c).
#
# The node is vendor/REALITY itself, the server a stock node runs, with hook.go added so it can seal
# any record and write past the record layer. Built with Xray's setup — SessionTicketsDisabled, and
# DetectPostHandshakeRecordsLens run at start, as Xray runs it when it loads an inbound (see the
# empty records below for what it finds here). Both clients dial it, one scenario at a time:
#
#   none                     nothing wrong — the stream as a stock node leaves it
#   ccs ccs2 ccs0 ccsbig     a ChangeCipherSpec in the clear: right, wrong byte, empty, over 2^14
#   vers huge                a header with version 0x0301, a length over 2^14 + 256
#   junk tiny palert phs     records that do not open: random, shorter than a tag, a plain alert and
#                            a plain handshake record
#   nst nstsplit nstbad      a NewSessionTicket: whole, split across two records, not unmarshalling
#   nst32 nst33              32 and 33 of them in one record — maxUselessRecords is 32
#   hs0 hsunknown hsfin      an empty handshake record, an unknown message type, a Finished
#   hsbig hscert hscertok    a declared length over 64 KiB, a Certificate over 256 KiB, one under it
#                            (which then waits for its body, and the reply below interrupts it)
#   partccs                  half a ticket, then a ChangeCipherSpec
#   alertbad alert alertwarn close   an alert of three bytes, fatal, warning, close_notify
#   closelate alertlate      close_notify and a fatal alert once the VLESS response has arrived
#   closemore                a line after close_notify, in the same flight — nothing past the end is read
#   closeslow                the same behind 8 MB the client is slow to take — see slow() in node/main.go.
#                            ⚠️ It does not reach what it was written for: see the guard at the top
#                            of records_ready. It checks that 8 MB behind a slow reader arrive whole.
#   type24                   a record of an inner type TLS does not have
#   empty30 .. empty33       that many empty application-data records in a row
#   ku kureq ku2 kusplit kumix   a KeyUpdate: plain, asking for one back, two in a record, cut across
#                            two records, between two tickets — the node's write key moved on after it
#   kufull                   a KeyUpdate asking for an answer while the client's way to the node is
#                            full: 48 MB up that the node leaves unread for two seconds — see
#                            kufull in node/main.go
#   tagonly maxin bigin      a record of nothing but a tag; an inner plaintext of 2^14 + 1, and one more
#   zeros outer22            one of nothing but padding; one sealed under a handshake header
#   hugeahead                `huge` again, last: by now this client's process has the threads that
#                            open records ahead, and reads the socket ahead of the reference with the
#                            reference's reads in the shadow (O3, node_read_ahead in lc-tunnel) — the
#                            reset has to come from the shadow there, not from the socket. Early in
#                            the list, as `huge` is, no read yet has brought two records and the
#                            reads are still the reference's own
#
# and four in the handshake itself, which a stock node never sends — see hook.go:
#
#   alpn                     h2 chosen, nothing else
#   alps alpsold             h2 and application settings (ALPS) under the codepoint Chrome offers now,
#                            and under the old one: uTLS answers them with an EncryptedExtensions of
#                            its own after the server's Finished, and the node takes it into the
#                            transcript — so the client's Finished verifies only if it hashed it too
#   alpsnoalpn               settings with no protocol chosen, which uTLS refuses with
#                            unsupported_extension
#
# Run from the repository root, in the build image with the network on (it builds Xray and the
# node), after `make build/lc-tunnel`:
#
#   docker run --rm -v "$PWD:/repo" lc-build:local sh /repo/tools/vendorcap/nodealert/run.sh
#
# `-e LC_TUNNEL=/repo/…` runs another build of lc-tunnel — a mutant, which is what this stand is
# for where the gate cannot reach: the part of lc-tunnel that carries tls/post.c's verdicts to the
# socket. `-e SCENARIOS="close closemore"` runs only those.
#
# ONE LINE PER CONNECTION, from the node:
#
#   client ee  the EncryptedExtensions the client answered the node's with, as the node took it —
#            - for none
#   first    what the client did within 400 ms of the misbehaviour: alert:<name> — the alert it
#            sent, as the node's own read reports it; EOF — close_notify; silent — nothing
#   then     when it stayed silent, the node sends a VLESS response header and a line, and reads
#            again; then close_notify of its own and a last read
#   wrote    every record the client wrote after the misbehaviour began, outer type/body length,
#            and fin when it closed its side. 23/19 is an alert or a close_notify — sealed, so a
#            path sees the length and not which
#
# and the probe's line: `OK <scenario>` when the reply reached the application behind the client.
#
# ⚠️ THE ALERT'S NUMBER IS NOT ON THE WIRE — it is sealed. The node reads it with the client's key,
# which is how `first` can name it; a path sees `wrote`, and that is the half that must match for the
# difference to be invisible. Both halves are compared.
#
# ⚠️ THE EMPTY RECORDS COUNT FROM THE NODE'S OWN, WHERE IT HAS ANY. A stock node sends empty records
# in its target's post-handshake lengths (vendor/REALITY/tls.go:419-435), and the reference counts
# them with the scenario's (maxUselessRecords, vendor/utls/common.go:73). On this stand it sends
# none: the target's certificate is self-signed, the node's probe of it fails its own handshake and
# records no lengths — so both clients tip at 33, empty32 read and empty33 refused, as test/post has
# it. Against a real target the tipping point moves by the target's count, the same for both.
set -u
LC=$(cd "$(dirname "$0")/../../.." && pwd)   # the repository root, wherever it is mounted
HERE=$LC/tools/vendorcap/nodealert
SHAPE=$LC/tools/vendorcap/wireshape
W=/tmp/nodealert; rm -rf $W; mkdir -p $W; cd $W
say() { printf '\n== %s\n' "$*"; }

(cd $LC/vendor/Xray-core && go build -o $W/xray ./main) > $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
cp -r $LC/vendor/REALITY $W/reality && cp $HERE/hook.go $W/reality/zz_stand.go || exit 1
# The three calls the alps scenarios need, spliced into the copy — see hook.go. Each is checked to
# have landed: a splice that silently missed would run the alps scenarios as `none`, and both
# clients would agree about nothing having happened.
perl -0pi -e 's{(\t\t\t\t\tb\.AddBytes\(m\.echRetryConfigs\)\n\t\t\t\t\}\)\n\t\t\t\}\n)}{$1\t\t\tstandALPSExt(b)\n}' $W/reality/handshake_messages.go
perl -0pi -e 's{\tencryptedExtensions\.alpnProtocol = c\.clientProtocol\n}{\tencryptedExtensions.alpnProtocol = standALPN(c.clientProtocol)\n}' $W/reality/handshake_server_tls13.go
perl -0pi -e 's{padding = hc\.handshakeLen\[2\]\n}{padding = hc.handshakeLen[2] + standALPSLen()\n}' $W/reality/conn.go
perl -0pi -e 's{(\t\t\terr = hs\.(?:handshake|readClientFinished)\(\)\n)}{$1\t\t\tStandHandshakeErr = err\n}g' $W/reality/tls.go
perl -0pi -e 's{(func \(hs \*serverHandshakeStateTLS13\) sendSessionTickets\(\) error \{\n\tc := hs\.c\n\n)}{$1\tstandSavePre(hs.transcript, hs.suite.hash)\n}' $W/reality/handshake_server_tls13.go
perl -0pi -e 's{(func \(hs \*serverHandshakeStateTLS13\) readClientFinished\(\) error \{\n\tc := hs\.c\n)}{$1\tif took, err := c.standTakeClientEE(standPre); err != nil {\n\t\treturn err\n\t} else if took {\n\t\ths.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, standPre)\n\t}\n}' $W/reality/handshake_server_tls13.go
for s in "handshake_messages.go standALPSExt(b)" "handshake_server_tls13.go standALPN(c.clientProtocol)" \
         "conn.go + standALPSLen()" "handshake_server_tls13.go standSavePre(hs.transcript, hs.suite.hash)" \
         "handshake_server_tls13.go c.standTakeClientEE(standPre)" "tls.go StandHandshakeErr = err"; do
    grep -qF "${s#* }" $W/reality/${s%% *} || { echo "SPLICE MISSED: $s"; exit 1; }
done
mkdir $W/reality/nodealert && cp $HERE/node/main.go $W/reality/nodealert/ &&
	(cd $W/reality && go build -o $W/node ./nodealert) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
for p in target probe; do
    (cd $SHAPE/$p && go build -o $W/$p.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
done
TUN=${LC_TUNNEL:-$LC/build/lc-tunnel}
[ -x "$TUN" ] || { echo "NO $TUN: make build/lc-tunnel first"; exit 1; }
cp "$TUN" $W/lc-tunnel

keys=$($W/xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
pub=$(printf '%s\n' "$keys" | awk -F': *' '/Password|Public/{print $2; exit}')
UUID=00000000-0000-4000-8000-000000000001

cat > $W/client.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":19990,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18080,"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":14480,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.avito.ru","fingerprint":"firefox","publicKey":"$pub","password":"$pub","shortId":"0123abcd"}}}]}
JSON

echo "warm none" > $W/scenario
$W/target.bin > $W/target.log 2>&1 &
sleep 1
$W/node 127.0.0.1:14480 127.0.0.1:18443 "$priv" 0123abcd www.avito.ru $W/scenario > $W/node.log 2>&1 &
sleep 3
$W/xray run -c $W/client.json > $W/client.log 2>&1 &
$W/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14480 www.avito.ru "$pub" 0123abcd \
    $UUID 19991 -t 127.0.0.1:18080 -f xtls-rprx-vision -w 1 > $W/tun.log 2>&1 &
sleep 3
# The reference's first connection on a fresh server usually fails — see the wireshape stand.
for warm in 19990 19991; do $W/probe.bin tcp 127.0.0.1:$warm > /dev/null; done
sleep 4

SCENARIOS=${SCENARIOS:-"none alpn alps alpsold alpsnoalpn ccs ccs2 ccs0 ccsbig vers huge junk tiny palert phs
           nst nstsplit nstbad nst32 nst33 hs0 hsunknown hsfin hsbig hscert hscertok partccs
           alertbad alert alertwarn close type24 closelate alertlate closemore closeslow empty30 empty31 empty32 empty33
           ku kureq ku2 kusplit kumix kufull tagonly maxin bigin zeros outer22 hugeahead"}
: > $W/probes
for sc in $SCENARIOS; do
    for who in ref:19990 lc:19991; do
        n=${who%%:*}; p=${who#*:}
        echo "$n $sc" > $W/scenario
        mode=tcp; [ "$sc" = closeslow ] && mode=tcplate
        [ "$sc" = kufull ] && mode=tcpup
        echo "$n $sc $($W/probe.bin $mode 127.0.0.1:$p | tr ' ' '_')" >> $W/probes
        sleep 1
    done
done
sleep 3

for p in /proc/[0-9]*; do
    case "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" in
        "$W"/*) kill "${p#/proc/}" 2>/dev/null ;;
    esac
done
wait

# SIDE BY SIDE, and the verdict: the same alert, the same records on the wire, the same line at the
# far end. The exit status is this client's — a scenario where the two differ.
say "per scenario (ref, then lc)"
bad=0
for sc in $SCENARIOS; do
    r=$(awk -v s="$sc" '$1 == "ref" && $2 == s' $W/node.log | tail -1)
    l=$(awk -v s="$sc" '$1 == "lc" && $2 == s' $W/node.log | tail -1)
    # And the probe's error names both of its ports: the one it dialled differs by client, and the
    # one it dialled from by run.
    rp=$(awk -v s="$sc" '$1 == "ref" && $2 == s { print $3 }' $W/probes | tail -1 | sed 's/127\.0\.0\.1:[0-9]*/127.0.0.1:*/g')
    lp=$(awk -v s="$sc" '$1 == "lc" && $2 == s { print $3 }' $W/probes | tail -1 | sed 's/127\.0\.0\.1:[0-9]*/127.0.0.1:*/g')
    # A refused handshake is reported with the client's port in it, which differs by construction.
    rs=$(printf '%s' "$r" | cut -d'|' -f2- | sed 's/127\.0\.0\.1:[0-9]*/127.0.0.1:*/g')
    ls=$(printf '%s' "$l" | cut -d'|' -f2- | sed 's/127\.0\.0\.1:[0-9]*/127.0.0.1:*/g')
    if [ -n "$rs" ] && [ "$rs" = "$ls" ] && [ "$rp" = "$lp" ]; then v=same; else v=DIFF; bad=1; fi
    printf '%-10s %s\n  ref%s  probe %s\n  lc %s  probe %s\n' "$sc" "$v" "$rs" "$rp" "$ls" "$lp"
done
say "lc-tunnel said"; grep -v '^$' $W/tun.log | tail -40
exit $bad
