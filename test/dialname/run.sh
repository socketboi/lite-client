#!/bin/sh
# A REALITY NODE GIVEN BY NAME, dialled by this client and by the Xray client side by side.
#
# The reference looks the name up for every dial and dials it as Go's net.Dialer does: sixteen
# seconds for the lookup and the connects together, the addresses of the first one's family tried in
# order, each given an equal share of the time left but no less than two seconds, and the other
# family raced 300 ms behind (src/net/dial.h has the citations). This client looked the name up once
# at start, refused to start without an answer, and connected to the first address it got — with no
# second address tried once that connect had started — until 2026-09-29.
#
# The addresses are loopback ones in /etc/hosts — the node on 127.0.0.5, holes on .4 and .6 — whose
# order both clients keep: both look them up with Go's own resolver now (this one through its
# transcription, net/goresolve.h), and it does not apply the longest-prefix rule to IPv4
# (GOROOT/src/net/addrselect.go:183-202). When this client asked getaddrinfo, glibc here did apply it,
# which the three addresses defeated by sharing 29 bits with the source, 127.0.0.1.
#
# A HOLE is an address whose SYNs go unanswered — see tool/main.go — and which only the dialer's
# clock gets past. Each scenario asks once through each client and times it:
#
#   one       the node's address alone                         both at once
#   hole      a hole, then the node                            both after 16/2 = 8 s
#   holes     two holes, then the node                         both after 16/3 + 10.7/2 = 10.7 s
#   v6hole    ::1 as a hole, then the node on 127.0.0.5        both after the fallback's 300 ms
#   noname    a name with no address                           both fail, and this client started
#   moved     the name moved to where nothing listens          both fail, and are back when it is back
#
# `holes` and `v6hole` are the ones the old dial could not pass at all: it spent every attempt on the
# first address.
#
# Run from the repository root:
#
#	sh test/dialname/run.sh
#
# LC_TUNNEL=<path under the repository root> runs another build instead of building this tree's —
# the control: the build before 2026-09-29 refuses to start, and fails `hole`, `holes` and `v6hole`.
set -e

IMG=lc-build:local
OUT=build-stand
W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

# Decided here and not in the container's shell: a "${LC_TUNNEL:-}" inside the double-quoted script below
# closed its quotes, left `[ -n ]`, which is true, and nothing was built: until 2026-09-30 the stand
# dialled whatever build-stand/lc/lc-tunnel an earlier make had left there.
BUILD_LC="make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel"
[ -z "${LC_TUNNEL:-}" ] || BUILD_LC=:
docker run --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod -w /w "$IMG" sh -c "
set -e
$BUILD_LC
(cd /w/test/dialname/tool && go build -o /w/$OUT/dialname-tool .)
[ -x /w/$OUT/ref-xray ] || (cd vendor/Xray-core && /usr/local/go1.27/bin/go build -o /w/$OUT/ref-xray ./main)
[ -x /w/$OUT/ws-target ] || (cd tools/vendorcap/wireshape/target && go build -o /w/$OUT/ws-target .)
" >/dev/null

docker run -i --rm -v "$W:/w" -w /w -e LC=/w/${LC_TUNNEL:-$OUT/lc/lc-tunnel} "$IMG" sh -s <<'SH'
set -u
S=/w/build-stand
T=/tmp/dn; rm -rf $T; mkdir -p $T
fail=0
keys=$($S/ref-xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
pub=$(printf '%s\n' "$keys" | awk -F': *' '/Password|Public/{print $2; exit}')
U=00000000-0000-4000-8000-000000000001
cat > $T/server.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.5","port":14470,"protocol":"vless",
   "settings":{"clients":[{"id":"$U","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:18443","serverNames":["www.avito.ru"],"privateKey":"$priv","shortIds":["d1a1ed00"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
cat > $T/client.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":19990,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":9300,"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"node.test","port":14470,"users":[{"id":"$U","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"www.avito.ru","fingerprint":"firefox","publicKey":"$pub","password":"$pub","shortId":"d1a1ed00"}}}]}
JSON

cp /etc/hosts $T/hosts.base
hosts() {
	cp $T/hosts.base /etc/hosts
	for a in "$@"; do echo "$a node.test" >> /etc/hosts; done
	# Go keeps what it read of /etc/hosts for five seconds (GOROOT/src/net/hosts.go:16,
	# cacheMaxAge), so the reference would dial the previous scenario's addresses without this.
	sleep 6
}

$S/ws-target > $T/target.log 2>&1 &
$S/dialname-tool echo 127.0.0.1:9300 &
$S/ref-xray run -c $T/server.json > $T/server.log 2>&1 &
for h in 4:127.0.0.4 6:127.0.0.6 v6:[::1]; do
	$S/dialname-tool hole "${h#*:}:14470" > $T/hole${h%%:*}.log 2>&1 &
done
sleep 3
for h in 4 6; do
	grep -q 'hole ready' $T/hole$h.log || { echo "  FAIL  no hole: $(cat $T/hole$h.log)"; exit 1; }
done
v6=0
grep -q 'hole ready' $T/holev6.log && v6=1

# NO ADDRESS AT ALL WHEN THE CLIENTS START: the reference starts regardless, and so must this client.
hosts
$S/ref-xray run -c $T/client.json > $T/client.log 2>&1 &
$LC /w/package/files/fingerprint.fpt node.test 14470 www.avito.ru "$pub" d1a1ed00 \
	$U 19991 -t 127.0.0.1:9300 -f xtls-rprx-vision -w 1 > $T/tun.log 2>&1 &
lcpid=$!
sleep 2
if kill -0 $lcpid 2>/dev/null; then echo "  ok    this client started with a name that does not resolve"
else echo "  FAIL  this client refused to start: $(tail -2 $T/tun.log)"; fail=1; fi

run() { # scenario, then what each answer must look like: ok:MIN:MAX or fail
	sc=$1; want=$2
	for who in ref:19990 lc:19991; do
		r=$($S/dialname-tool ask 127.0.0.1:${who#*:})
		verdict=ok
		case "$want" in
		fail) case "$r" in fail*) ;; *) verdict=FAIL ;; esac ;;
		ok:*)
			lo=$(echo "$want" | cut -d: -f2); hi=$(echo "$want" | cut -d: -f3)
			ms=$(echo "$r" | awk '{print $2}')
			case "$r" in ok*) [ "$ms" -ge "$lo" ] && [ "$ms" -le "$hi" ] || verdict=FAIL ;; *) verdict=FAIL ;; esac ;;
		esac
		[ $verdict = ok ] || fail=1
		printf '  %-5s %-8s %-4s %s\n' $verdict "$sc" ${who%%:*} "$r"
	done
}

hosts 127.0.0.5
# The reference's first connection on a fresh server is thrown away — see the wireshape stand.
for p in 19990 19991; do $S/dialname-tool ask 127.0.0.1:$p > /dev/null; done
sleep 1

echo "=== in the order getaddrinfo gives them here: $(hosts 127.0.0.4 127.0.0.6 127.0.0.5; getent ahostsv4 node.test | awk '$2=="STREAM"{printf "%s ", $1}')"
hosts 127.0.0.5;                      run one    ok:0:1500
hosts 127.0.0.4 127.0.0.5;            run hole   ok:7500:9500
hosts 127.0.0.4 127.0.0.6 127.0.0.5;  run holes  ok:10000:12000
if [ $v6 = 1 ]; then
	hosts ::1 127.0.0.5;              run v6hole ok:250:1500
else
	echo "  skip  v6hole: no ::1 in this container ($(cat $T/holev6.log))"
fi
hosts;                                run noname fail
hosts 127.0.0.9;                      run moved  fail
hosts 127.0.0.5;                      run back   ok:0:1500

# Go's own error, "lookup node.test on SERVER: ..." (net/goresolve.h), as the reference words it.
n=$(grep -c 'cannot reach the node: lookup node.test' $T/tun.log || true)
echo "  lookups this client said failed: $n"
[ "$n" -ge 5 ] || { echo "  FAIL  a name with no address is asked for on every attempt, five of them"; fail=1; }

if [ $fail -eq 0 ]; then
	echo "  ok    both clients dial a name the same way"
else
	echo "  --- this client's log"; tail -20 $T/tun.log; echo "  --- the reference's log"; tail -30 $T/client.log
	exit 1
fi
SH
