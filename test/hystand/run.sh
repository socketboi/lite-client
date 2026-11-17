#!/bin/sh
# The reference Hysteria2 server, an echo target behind it, and this client between them.
# Run from the repository root. See test/hystand/README, including the control.
set -e

IMG=lc-build:local
NET=lcnet
OUT=build-stand                 # ignored by .gitignore, like every other build directory

# Git Bash on Windows hands docker an MSYS path it cannot mount; `pwd -W` gives the real one and
# MSYS_NO_PATHCONV stops the rewriting of arguments that look like paths. Both are no-ops elsewhere.
W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

in_image() {
	docker run --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod \
		-w /w "$IMG" sh -c "$1"
}

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

echo "building: reference server, echo target, loader, client"
in_image "
set -e
mkdir -p /w/$OUT
sh test/hystand/build-reference.sh /w/$OUT
cd /w/test/hystand/echo
go build -o /w/$OUT/echo-srv .
cd /w/test/hystand/load
go build -o /w/$OUT/load-cli .
cd /w
[ -f $OUT/cert.pem ] || {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem \
        -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null
    openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt
}
make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel
"

cat > "$OUT/server.yaml" <<YAML
listen: :4443
tls:
  cert: /w/$OUT/cert.pem
  key: /w/$OUT/key.pem
auth:
  type: password
  password: standpass
YAML

PIN=$(cat "$OUT/pin.txt")
docker rm -f hystand-srv hystand-cli >/dev/null 2>&1 || true
trap 'docker rm -f hystand-srv hystand-cli >/dev/null 2>&1 || true' EXIT

# The server's hysteria is not the container's first process, so that it can be stopped and started
# again with the container — and its address — still there: see the ICMP check below.
docker run -d --name hystand-srv --network "$NET" -v "$W:/w" -w /w "$IMG" \
	sh -c "/w/$OUT/echo-srv & /w/$OUT/ref-hysteria server -c /w/$OUT/server.yaml & echo \$! > /tmp/hy.pid; wait" >/dev/null
docker run -d --name hystand-cli --network "$NET" -v "$W:/w" -w /w -e LC_OPEN_LOG=1 "$IMG" \
	sh -c "exec /w/$OUT/lc/lc-tunnel -H hystand-srv 4443 www.avito.ru standpass - 1080 \
	       -t 127.0.0.1:9000 -p $PIN" >/dev/null

# The client listens only once its first connection is made, as the reference registers its modes
# only once its client exists — so this line appearing means the connection is up and a dial lands.
n=0
until docker logs hystand-cli 2>&1 | grep -q "listening on 1080"; do
	n=$((n + 1))
	[ $n -le 75 ] || { echo "  FAIL  the client never listened"; docker logs hystand-cli 2>&1 | tail -5; exit 1; }
	sleep 0.2
done

echo "=== 32 MB up and back"
docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 33554432 || exit 1

# AND WHAT THE WRITE LOOP DID WHILE CARRYING IT, asked the way a router is asked: SIGUSR1, which the
# client answers on the turn after. Printed rather than asserted — it is a shape, not a contract.
# What the three numbers mean is at their declaration in src/quic/conn.h; the short of it is that a
# pass ended by the pace is the reference's own behaviour and one ended with nothing left to write is
# this loop going back to the poll. One transfer of 32 MB tells them apart by an order of magnitude.
docker kill --signal=USR1 hystand-cli >/dev/null 2>&1 || true
sleep 1
docker logs hystand-cli 2>&1 | grep -E "chunks in|write loop:|replaced connection" | tail -3 | sed 's/^/  /'

echo "=== 64 KB, twenty times, a fresh connection each"
n=0
while [ $n -lt 20 ]; do
	docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 >/dev/null || {
		echo "  FAIL  run $n did not come back whole"
		exit 1
	}
	n=$((n + 1))
done
echo "  ok    twenty short connections, each byte for byte"

# Four at once, so that packets carry frames of several streams — the coalescing in flush. A stream
# whose accepted bytes were counted wrongly while sharing a packet comes back with a MISMATCH.
echo "=== 8 MB, four streams at once"
pids=""
for k in 1 2 3 4; do
	docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 8388608 > "$OUT/par$k.log" 2>&1 &
	pids="$pids $!"
done
bad=0
for p in $pids; do wait "$p" || bad=1; done
for k in 1 2 3 4; do grep -q "^ok " "$OUT/par$k.log" || { bad=1; cat "$OUT/par$k.log"; }; done
[ "$bad" -eq 0 ] || { echo "  FAIL  a stream sharing packets did not come back whole"; exit 1; }
echo "  ok    four concurrent streams, each byte for byte"

docker logs hystand-cli 2>&1 | tail -5

# THE CONNECTION'S LIFE, which is the reference's reconnectableClientImpl
# (vendor/hysteria/core/client/reconnect.go): made when a request needs it, never while nobody asks,
# and one attempt per request that finds none. The node is PAUSED rather than stopped, so its name
# still resolves and every packet towards it goes unanswered — a path that died, not a refused one.
attempts() {
	docker logs hystand-cli 2>&1 | grep -c "did not complete a QUIC handshake\|cannot reach the node" || true
}

echo "=== the node goes silent: the connection ends on its idle timeout, in silence"
docker pause hystand-srv >/dev/null
sleep 45
docker logs hystand-cli 2>&1 | grep -q "ERR_IDLE_CLOSE" || {
	echo "  FAIL  no idle close 45 s after the node went silent"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
}
echo "  ok    idle close"

echo "=== nobody asks: nothing is dialled"
before=$(attempts)
sleep 20
after=$(attempts)
[ "$after" -eq "$before" ] || {
	echo "  FAIL  $((after - before)) connect attempts in 20 s with no requests"
	exit 1
}
echo "  ok    no attempts in 20 s"

# THE FIRST REQUEST AFTER THE CONNECTION DIED FAILS AT ONCE AND DIALS NOTHING: clientDo hands it the
# client it still holds, OpenStream fails on the closed connection, and only that failure clears the
# client (vendor/hysteria/core/client/reconnect.go:63-88). ⚠️ Until 2026-09-27 this stand expected an
# attempt here, the model the client had then; the one after it is the request that dials.
echo "=== the first request after the connection died: refused at once, nothing dialled"
t0=$(date +%s)
out=$(docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1) && {
	echo "  FAIL  a request came back with the node paused: $out"
	exit 1
}
took=$(($(date +%s) - t0))
made=$(($(attempts) - after))
[ "$made" -eq 0 ] && [ "$took" -le 2 ] || {
	echo "  FAIL  $made attempts, request ended after $took s (want none, at once)"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
}
echo "  ok    no attempt, the request ended after $took s"

echo "=== the next request while the node is silent: one attempt, failed by the handshake's idle clock"
t0=$(date +%s)
out=$(docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1) && {
	echo "  FAIL  a request came back with the node paused: $out"
	exit 1
}
took=$(($(date +%s) - t0))
made=$(($(attempts) - after))
[ "$made" -eq 1 ] && [ "$took" -ge 4 ] && [ "$took" -le 12 ] || {
	echo "  FAIL  $made attempts, request ended after $took s (want 1 attempt, 5 s of silence)"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
}
echo "  ok    one attempt, the request ended after $took s"

echo "=== the node answers again: the next request makes the connection itself"
docker unpause hystand-srv >/dev/null
out=$(docker exec hystand-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1) || {
	echo "  FAIL  the first request after the node came back: $out"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
}
echo "  ok    $out"

# THE NODE'S PORT CLOSES WITH THE HOST STILL THERE, so every packet to it is answered by the kernel
# with ICMP port unreachable. The reference's socket is unconnected and never hears of that: the
# connection lives until its idle timeout. A connected socket turned the first such ICMP into
# "cannot receive: Connection refused" and ended the connection at once.
idle_closes() {
	docker logs hystand-cli 2>&1 | grep -c "ERR_IDLE_CLOSE" || true
}
ended() {
	docker logs hystand-cli 2>&1 | grep -c "the node's connection ended" || true
}
echo "=== the node's port closes: ICMP does not end the connection, the idle timeout does"
before=$(ended)
idle_before=$(idle_closes)
docker exec hystand-srv sh -c 'kill -9 $(cat /tmp/hy.pid)'   # KILL: a server that closes politely would say so first
sleep 20
if docker logs hystand-cli 2>&1 | grep -q "Connection refused" || [ "$(ended)" -ne "$before" ]; then
	echo "  FAIL  the connection ended within 20 s of the port closing"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
fi
sleep 25
[ "$(idle_closes)" -gt "$idle_before" ] || {
	echo "  FAIL  no idle close 45 s after the port closed"
	docker logs hystand-cli 2>&1 | tail -5
	exit 1
}
echo "  ok    alive for 20 s of ICMP, then the idle timeout"
docker exec -d hystand-srv sh -c "/w/$OUT/ref-hysteria server -c /w/$OUT/server.yaml"

# AND A CLIENT STARTED WHILE THE NODE IS SILENT EXITS, as the reference's does with "failed to
# initialize client" (vendor/hysteria/app/cmd/client.go:867-869) — status 1, after the handshake's
# five seconds of silence, and without ever having listened.
echo "=== a client started against a silent node exits with 1 and never listens"
docker pause hystand-srv >/dev/null
t0=$(date +%s)
set +e
out=$(docker run --rm --network "$NET" -v "$W:/w" -w /w "$IMG" \
	sh -c "exec timeout 30 /w/$OUT/lc/lc-tunnel -H hystand-srv 4443 www.avito.ru standpass - 1081 -t 127.0.0.1:9000 -p $PIN" 2>&1)
rc=$?
set -e
took=$(($(date +%s) - t0))
docker unpause hystand-srv >/dev/null
if [ "$rc" -ne 1 ] || [ "$took" -lt 4 ] || [ "$took" -gt 15 ] ||
	! printf '%s\n' "$out" | grep -q "failed to initialize client" ||
	printf '%s\n' "$out" | grep -q "listening on"; then
	echo "  FAIL  exit $rc after $took s:"
	printf '%s\n' "$out" | tail -5
	exit 1
fi
echo "  ok    exit 1 after $took s, never listened"
