#!/bin/sh
# A STREAM THE NODE ENDS BEFORE ITS ANSWER, and what the client does with its connection then.
#
# To the reference that is ReadTCPResponse failing, which wrapIfConnectionClosed makes ClosedError:
# the request fails, and reconnectableClientImpl lets go of its client — `rc.client = nil` — so the
# next request dials a new connection (vendor/hysteria/core/client/client.go:216-220, :251-262,
# vendor/hysteria/core/client/reconnect.go:80-88). Letting go is not closing: what already rides the
# old connection goes on riding it.
#
# A node that does this is not the reference's server — it answers every request it can read — so
# the stand makes one: the reference server built with an overlay of core/server/server.go that ends
# the Nth TCP stream right after reading its request, without a word (HYSTAND_CLOSE_NTH). vendor/ is
# not written; the overlay changes what the compiler reads.
#
# The script, for this client and then for the reference client as the control:
#   1  a long transfer, 512 MB up and back, left running
#   2  a short one, which goes on the same connection
#   3  a short one, which the node ends: it fails
#   4  a short one, which makes a second connection and goes on it
# and then the long one must finish byte for byte, on the first connection, which nobody closed. The
# node's log counts the connections: two for each client.
#
# Run from the repository root, after test/hystand/run.sh has built build-stand/:
#
#	sh test/hystand/closed.sh
set -e

IMG=lc-build:local
NET=lcnet
OUT=build-stand
W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

echo "building: the reference server that ends a stream, and this client"
docker run -i --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod -w /w "$IMG" sh -s <<SH
set -e
mkdir -p /w/$OUT/closesrv
src=/w/vendor/hysteria/core/server/server.go
# The hook, after ReadTCPRequest: the Nth stream is closed as a failed read closes it.
awk '
	/^import \(/ { print; print "\t\"os\""; print "\t\"strconv\""; print "\t\"sync/atomic\""; next }
	/reqAddr, err := protocol.ReadTCPRequest\(stream\)/ {
		print
		getline; print; getline; print; getline; print; getline; print
		print "\tif n, _ := strconv.Atoi(os.Getenv(\"HYSTAND_CLOSE_NTH\")); n > 0 && atomic.AddInt64(&hystandStreams, 1) == int64(n) {"
		print "\t\t_ = stream.Close()"
		print "\t\treturn"
		print "\t}"
		next
	}
	{ print }
	END { print "var hystandStreams int64" }
' \$src > /w/$OUT/closesrv/server.go
grep -q HYSTAND_CLOSE_NTH /w/$OUT/closesrv/server.go
printf '{"Replace":{"%s":"%s"}}\n' \$src /w/$OUT/closesrv/server.go > /w/$OUT/closesrv/ov.json
cd /w/vendor/hysteria/app && GOWORK=off go build -mod=readonly -overlay /w/$OUT/closesrv/ov.json -o /w/$OUT/ref-hysteria-close .
cd /w && make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel
SH

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
cat > "$OUT/refcli-closed.yaml" <<YAML
server: cl-srv:4443
auth: standpass
tls:
  sni: www.avito.ru
  insecure: true
tcpForwarding:
  - listen: 127.0.0.1:1080
    remote: 127.0.0.1:9000
YAML

docker rm -f cl-srv cl-cli >/dev/null 2>&1 || true
trap 'docker rm -f cl-srv cl-cli >/dev/null 2>&1 || true' EXIT

fail=0
for who in lc ref; do
	echo "=== $who"
	docker rm -f cl-srv cl-cli >/dev/null 2>&1 || true
	docker run -d --name cl-srv --network "$NET" -v "$W:/w" -w /w -e HYSTAND_CLOSE_NTH=3 "$IMG" \
		sh -c "/w/$OUT/echo-srv & exec /w/$OUT/ref-hysteria-close server -c /w/$OUT/server.yaml --log-level debug" >/dev/null
	sleep 2
	if [ $who = lc ]; then
		cmd="exec /w/$OUT/lc/lc-tunnel -H cl-srv 4443 www.avito.ru standpass - 1080 -t 127.0.0.1:9000 -p $PIN"
		ready="listening on 1080"
	else
		# Without its update check, which is a stream of its own through the tunnel at start
		# (vendor/hysteria/app/cmd/client.go:862) and would be the node's first TCP stream.
		cmd="exec /w/$OUT/ref-hysteria client -c /w/$OUT/refcli-closed.yaml --disable-update-check"
		ready="TCP forwarding listening"
	fi
	docker run -d --name cl-cli --network "$NET" -v "$W:/w" -w /w "$IMG" sh -c "$cmd" >/dev/null
	n=0
	until docker logs cl-cli 2>&1 | grep -q "$ready"; do
		n=$((n + 1))
		[ $n -le 100 ] || { echo "  FAIL  the client never listened"; docker logs cl-cli 2>&1 | tail -5; exit 1; }
		sleep 0.2
	done

	docker exec cl-cli "/w/$OUT/load-cli" 127.0.0.1:1080 536870912 > "$OUT/closed-long.log" 2>&1 &
	long=$!
	sleep 1
	r2=$(docker exec cl-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1 | tail -1) || true
	r3=$(docker exec cl-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1 | tail -1) || true
	sleep 1
	r4=$(docker exec cl-cli "/w/$OUT/load-cli" 127.0.0.1:1080 65536 2>&1 | tail -1) || true
	wait $long || true
	r1=$(tail -1 "$OUT/closed-long.log")
	conns=$(docker logs cl-srv 2>&1 | grep -c "client connected")

	echo "  1 long:  $r1"
	echo "  2 short: $r2"
	echo "  3 short: $r3"
	echo "  4 short: $r4"
	echo "  connections the node saw: $conns"
	case "$r1" in "ok 536870912 "*) ;; *) echo "  FAIL  the long transfer did not survive"; fail=1 ;; esac
	case "$r2" in "ok 65536 "*) ;; *) echo "  FAIL  the second request did not go through"; fail=1 ;; esac
	case "$r3" in "ok "*) echo "  FAIL  the request whose stream the node ended went through"; fail=1 ;; esac
	case "$r4" in "ok 65536 "*) ;; *) echo "  FAIL  the request after it did not go through"; fail=1 ;; esac
	[ "$conns" -eq 2 ] || { echo "  FAIL  $conns connections, where the request after the ended stream makes the second"; fail=1; }
done

[ $fail -eq 0 ] || exit 1
echo "  ok    both clients: the request fails, the next one dials, and the old connection carries on"
