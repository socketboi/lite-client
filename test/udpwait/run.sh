#!/bin/sh
# A REPLY THE CLIENT'S SOCKET WILL NOT TAKE YET, on both planes.
#
# Both references write a datagram back to the LAN with Go's WriteTo, and EAGAIN parks the goroutine
# until the socket has room: nothing is lost, and nothing behind it moves meanwhile
# (vendor/Xray-core/proxy/dokodemo/dokodemo.go:222-264; on the Hysteria2 plane
# vendor/hysteria/app/internal/tproxy/udp_linux.go:97-110, with the session's channel of
# udpMessageChanSize filling behind it, vendor/hysteria/core/client/udp.go:17, :125-141). This client
# dropped the datagram and went on, until 2026-09-28.
#
# A full send buffer is what a slow wireless LAN makes of a fast downlink, and a stand cannot make
# one: on a veth or loopback a datagram to a receiver with no room is lost at the receiver and the
# sender never sees EAGAIN. So the kernel's answer is faked instead — eagain.so, preloaded into
# lc-tunnel alone, fails every third datagram it sends to anything but the node's port 4443 with
# EAGAIN, and the socket is writable again at once, which is exactly the path a real stall takes
# through the code. A burst of 200 numbered datagrams (burst/) comes back through each plane: the
# control run without the shim, then with it. Every one of the 200, in order, or it is a FAIL.
#
# The control that the shim bites: the build before 2026-09-28 brings back 133 or 134 of 200 with it
# and all 200 without, on both planes and on both REALITY paths (xudp under Vision, and a 0x02
# stream without a flow).
#
# The reference clients cannot be run under the shim — Go makes its system calls itself, and a
# preloaded library never sees them. What they do is read off the lines above.
#
# Run from the repository root:
#
#	sh test/udpwait/run.sh
set -e

IMG=lc-build:local
NET=lcnet
OUT=build-stand
W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

echo "building: lc-tunnel, the shim, the burst, the reference servers"
docker run --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod -w /w "$IMG" sh -c "
set -e
mkdir -p /w/$OUT
make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel
cc -shared -fPIC -O2 -o /w/$OUT/eagain.so /w/test/udpwait/eagain.c -ldl
(cd /w/test/udpwait/burst && go build -o /w/$OUT/burst .)
[ -x /w/$OUT/ref-hysteria ] || (cd vendor/hysteria/app && go build -o /w/$OUT/ref-hysteria .)
[ -x /w/$OUT/ref-xray ] || (cd vendor/Xray-core && /usr/local/go1.27/bin/go build -o /w/$OUT/ref-xray ./main)
[ -x /w/$OUT/ws-target ] || (cd tools/vendorcap/wireshape/target && go build -o /w/$OUT/ws-target .)
[ -f /w/$OUT/cert.pem ] || {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem \
        -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null
    openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt
}
" >/dev/null

fail=0
check() {
	echo "  $1: $2"
	case "$2" in "200 of 200 back, in order: true") ;; *) fail=1 ;; esac
}

echo "=== the Hysteria2 plane"
PIN=$(cat "$OUT/pin.txt")
cat > "$OUT/server.yaml" <<YAML
listen: :4443
tls:
  cert: /w/$OUT/cert.pem
  key: /w/$OUT/key.pem
auth:
  type: password
  password: standpass
YAML
docker rm -f uw-srv uw-cli >/dev/null 2>&1 || true
trap 'docker rm -f uw-srv uw-cli >/dev/null 2>&1 || true' EXIT
docker run -d --name uw-srv --network "$NET" -v "$W:/w" -w /w "$IMG" \
	sh -c "/w/$OUT/burst -listen 127.0.0.1:9201 & exec /w/$OUT/ref-hysteria server -c /w/$OUT/server.yaml" >/dev/null
sleep 2
for shim in off on; do
	pre=""
	[ $shim = on ] && pre="LD_PRELOAD=/w/$OUT/eagain.so"
	docker rm -f uw-cli >/dev/null 2>&1 || true
	docker run -d --name uw-cli --network "$NET" -v "$W:/w" -w /w "$IMG" \
		sh -c "exec env $pre /w/$OUT/lc/lc-tunnel -H uw-srv 4443 www.avito.ru standpass - 1080 -u 5301@127.0.0.1:9201 -p $PIN" >/dev/null
	n=0
	until docker logs uw-cli 2>&1 | grep -q "listening on 1080"; do
		n=$((n + 1))
		[ $n -le 100 ] || { echo "  FAIL  the client never listened"; docker logs uw-cli 2>&1 | tail -5; exit 1; }
		sleep 0.2
	done
	sleep 1
	for k in 1 2 3; do
		check "EAGAIN $shim" "$(docker exec uw-cli /w/$OUT/burst -ask 127.0.0.1:5301 -n 200)"
	done
done
[ "$(docker logs uw-cli 2>&1 | grep -c 'eagain.so')" -eq 1 ] || { echo "  FAIL  the shim never failed a send"; fail=1; }
docker rm -f uw-srv uw-cli >/dev/null 2>&1 || true

echo "=== the REALITY plane"
out=$(docker run -i --rm -v "$W:/w" -w /w "$IMG" sh -s <<'SH'
set -u
S=/w/build-stand
T=/tmp/rw; rm -rf $T; mkdir -p $T
keys=$($S/ref-xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
pub=$(printf '%s\n' "$keys" | awk -F': *' '/Password|Public/{print $2; exit}')
U1=00000000-0000-4000-8000-000000000001
U2=00000000-0000-4000-8000-000000000002
cat > $T/server.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":14470,"protocol":"vless",
   "settings":{"clients":[{"id":"$U1","flow":"xtls-rprx-vision"},{"id":"$U2"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:18443","serverNames":["www.avito.ru"],"privateKey":"$priv","shortIds":["0123abcd"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
$S/ws-target > $T/target.log 2>&1 &
$S/ref-xray run -c $T/server.json > $T/server.log 2>&1 &
$S/burst -listen 127.0.0.1:15354 &
$S/burst -listen 127.0.0.1:53 &
sleep 2
for shim in off on; do
	pre=""; [ $shim = on ] && pre="LD_PRELOAD=$S/eagain.so"
	env $pre $S/lc/lc-tunnel /w/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
	    $U1 19971 -u 15300@127.0.0.1:15354 -f xtls-rprx-vision -w 1 > $T/tun1.log 2>&1 &
	p1=$!
	env $pre $S/lc/lc-tunnel /w/package/files/fingerprint.fpt 127.0.0.1 14470 www.avito.ru "$pub" 0123abcd \
	    $U2 19972 -u 15301@127.0.0.1:53 -w 1 > $T/tun2.log 2>&1 &
	p2=$!
	sleep 3
	for k in 1 2 3; do
		echo "EAGAIN $shim, xudp|$($S/burst -ask 127.0.0.1:15300 -n 200)"
		echo "EAGAIN $shim, 0x02|$($S/burst -ask 127.0.0.1:15301 -n 200)"
	done
	kill $p1 $p2 2>/dev/null; wait $p1 $p2 2>/dev/null
	[ $shim = on ] && echo "shim|$(cat $T/tun1.log $T/tun2.log | grep -c 'eagain.so')"
done
SH
)
printf '%s\n' "$out" | while IFS='|' read -r what result; do
	[ "$what" = shim ] && continue
	echo "$what|$result"
done > "$OUT/udpwait.reality"
while IFS='|' read -r what result; do check "$what" "$result"; done < "$OUT/udpwait.reality"
[ "$(printf '%s\n' "$out" | grep '^shim|' | cut -d'|' -f2)" = 2 ] || { echo "  FAIL  the shim never failed a send"; fail=1; }

if [ $fail -eq 0 ]; then
	echo "  ok    every burst came back whole and in order, on both planes, with sends failing EAGAIN"
else
	echo "  FAIL  a reply was lost or reordered"
	exit 1
fi
