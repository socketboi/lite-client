#!/bin/sh
# When the reference's garbage collector runs, which is when it closes a failed REALITY attempt's
# socket (DIVERGENCES.md G3): Xray-core v26.9.9 as a client, go1.27.1, with GODEBUG=gctrace=1,
# idle and then carrying traffic at several rates, and then failing handshakes one after another.
# Every GC line is kept with the phase it fell in; the summary gives the intervals per phase.
#
# Run from the repository root, in the build image:
#
#   docker run --rm -v "$PWD:/repo" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod \
#       lc-build:local sh /repo/tools/vendorcap/gcstand/run.sh
#
# `-e IDLE=250` seconds of idle (two forced cycles need more than 240), `-e SPAN=60` seconds per rate.
set -u
export PATH=/usr/local/go1.27/bin:$PATH
LC=$(cd "$(dirname "$0")/../../.." && pwd)
W=/tmp/gcstand; rm -rf $W; mkdir -p $W; cd $W
IDLE=${IDLE:-250}; SPAN=${SPAN:-60}
(cd $LC/vendor/Xray-core && go build -o $W/xray ./main) > $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
(cd $LC/tools/vendorcap/wireshape/target && go build -o $W/target.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
keys=$($W/xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
pub=$(printf '%s\n' "$keys" | awk -F': *' '/Password|Public/{print $2; exit}')
wrong=$($W/xray x25519 | awk -F': *' '/Password|Public/{print $2; exit}')
UUID=00000000-0000-4000-8000-000000000001
cat > $W/server.json <<JSON
{"log":{"loglevel":"info","access":"/tmp/gcstand/access.log"},
 "inbounds":[{"listen":"127.0.0.1","port":14470,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:18443","serverNames":["www.avito.ru"],"privateKey":"$priv","shortIds":["0123abcd"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
# the client: one inbound through the right key, one through a wrong one (every handshake fails)
cat > $W/client.json <<JSON
{"log":{"loglevel":"none"},
 "inbounds":[
  {"tag":"ok","listen":"127.0.0.1","port":19980,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18080,"network":"tcp"}},
  {"tag":"bad","listen":"127.0.0.1","port":19981,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18080,"network":"tcp"}}],
 "outbounds":[
  {"tag":"good","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":14470,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.avito.ru","fingerprint":"firefox","publicKey":"$pub","password":"$pub","shortId":"0123abcd"}}},
  {"tag":"wrong","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":14470,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.avito.ru","fingerprint":"firefox","publicKey":"$wrong","password":"$wrong","shortId":"0123abcd"}}}],
 "routing":{"rules":[{"type":"field","inboundTag":["bad"],"outboundTag":"wrong"},{"type":"field","inboundTag":["ok"],"outboundTag":"good"}]}}
JSON
$W/target.bin > $W/target.log 2>&1 &
$W/xray run -c $W/server.json > $W/server.log 2>&1 &
sleep 2
START=$(date +%s.%N)
GODEBUG=gctrace=1 $W/xray run -c $W/client.json > $W/client.out 2> $W/client.gc &
sleep 3
BYTES=$W/bytes; : > $BYTES
# a phase: its name, the time, how many REALITY handshakes the server has been through (its log
# says "REALITY" for every one it was handed) and how many bytes have been downloaded
mark() { echo "$1 $(awk -v s=$START -v n=$(date +%s.%N) 'BEGIN{printf "%.3f", n-s}') $(grep -c . $W/access.log 2>/dev/null || echo 0) $(awk '{s+=$1} END {printf "%d", s}' $BYTES)" >> $W/phases; }
curl -s -o /dev/null http://127.0.0.1:19980/down?bytes=1000 || true
mark idle; sleep $IDLE
for rate in 125K 625K 3125K 0; do
	mark "rate-$rate"
	end=$(( $(date +%s) + SPAN ))
	while [ $(date +%s) -lt $end ]; do
		if [ $rate = 0 ]; then curl -s -o /dev/null -w "%{size_download}
" -m $SPAN "http://127.0.0.1:19980/down?bytes=500000000" >> $BYTES || true
		else curl -s -o /dev/null -w "%{size_download}
" -m $SPAN --limit-rate $rate "http://127.0.0.1:19980/down?bytes=500000000" >> $BYTES || true; fi
	done
done
mark conn-5s
end=$(( $(date +%s) + SPAN )); while [ $(date +%s) -lt $end ]; do for k in 1 2 3 4 5; do curl -s -o /dev/null http://127.0.0.1:19980/down?bytes=1000 || true; done; sleep 1; done
mark fail-1s
end=$(( $(date +%s) + SPAN )); while [ $(date +%s) -lt $end ]; do curl -s -o /dev/null -m 2 http://127.0.0.1:19981/ || true; sleep 1; done
mark fail-fast
end=$(( $(date +%s) + SPAN )); while [ $(date +%s) -lt $end ]; do curl -s -o /dev/null -m 2 http://127.0.0.1:19981/ || true; done
mark end
# gctrace: "gc N @T.TTTs P%: ... A->B->C MB, D MB goal, ..." with "(forced)" for the periodic one
awk 'NR==FNR { ph[++np] = $1; at[np] = $2; next }
     /^gc [0-9]+ @/ { t = $3; sub(/@/, "", t); sub(/s$/, "", t); t += 0; p = "before"
       for (i = 1; i <= np; i++) if (t >= at[i]) p = ph[i]
       f = index($0, "(forced)") ? " forced" : ""
       m = $0; sub(/.*, /, "", m)
       heap = $0; sub(/.* ([0-9]+->[0-9]+->[0-9]+ MB).*/, "&", heap); match($0, /[0-9]+->[0-9]+->[0-9]+ MB, [0-9]+ MB goal/)
       printf "%-12s %9.3f%s  %s\n", p, t, f, substr($0, RSTART, RLENGTH) }' $W/phases $W/client.gc > $W/gc.lines
cat $W/gc.lines
echo "== intervals per phase"
awk '{ p = $1; t = $2; if (p in last) { d = t - last[p]; n[p]++; s[p] += d; if (!(p in mn) || d < mn[p]) mn[p] = d; if (d > mx[p]) mx[p] = d } last[p] = t; c[p]++ }
     END { for (p in c) printf "%-12s %4d GCs  interval %s\n", p, c[p], (p in n) ? sprintf("%.2f..%.2f s, mean %.2f", mn[p], mx[p], s[p]/n[p]) : "-" }' $W/gc.lines | sort
cat $W/phases
