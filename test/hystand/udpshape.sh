#!/bin/sh
# How many sockets the NODE opens for one client's UDP, which is the whole of the session-model
# question and the only part of it that an application can feel.
#
# The node keys its sessions by the SessionID the CLIENT chose and dials one UDP socket per session
# (vendor/hysteria/core/server/udp.go:309-340). So the client's session model decides the mapping a
# destination sees:
#
#   a session per pair      — every destination sees a different source port (endpoint-dependent,
#                             the mapping games and calls fail on)
#   one session per client  — every destination sees the same source port (endpoint-independent)
#
# The reference opens a session per pair: its tproxy path takes a (src, dst) pair at a time
# (vendor/hysteria/app/internal/tproxy/udp_linux.go:28-45, :47-64) and its forwarder keys by the
# local source (app/internal/forwarding/udp.go:129-149). SO DOES THIS CLIENT, since 16 September
# and by the maintainer's decision: on the Hysteria2 plane udp_session_for keys a datagram session by
# the client's whole sockaddr AND the destination. The REALITY plane still keeps one session per
# client, because there the reference is XUDP and an XUDP stream carries every destination at once.
#
# What is driven here is the forwarder shape, which both clients have: one fixed destination, two
# local sockets. BOTH open a session per local socket, so both come out of the node on two ports —
# which is the control, not the finding: it is how the stand shows it measures what it claims to.
# test/hystand/seen answers each datagram with the source it arrived from, so the answer is read
# off the far end rather than inferred.
#
# Run from the repository root:
#
#	sh test/hystand/udpshape.sh
set -e

IMG=lc-build:local
NET=lcnet
OUT=build-stand

W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

docker run -i --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod -w /w "$IMG" sh -s <<SH
set -e
cd /w
mkdir -p $OUT
sh test/hystand/build-reference.sh /w/$OUT
cd /w/test/hystand/seen && go build -o /w/$OUT/seen .
cd /w
[ -f $OUT/cert.pem ] || {
	openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem \
	    -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null
	openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt
}
make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel
SH

cat > "$OUT/server.yaml" <<YAML
listen: :4443
tls:
  cert: /w/$OUT/cert.pem
  key: /w/$OUT/key.pem
auth:
  type: password
  password: standpass
YAML

cat > "$OUT/udpcli.yaml" <<YAML
server: shape-srv:4443
auth: standpass
tls:
  sni: www.avito.ru
  insecure: true
udpForwarding:
  - listen: 127.0.0.1:5301
    remote: 127.0.0.1:9101
    timeout: 20s
  - listen: 127.0.0.1:5302
    remote: 127.0.0.1:9102
    timeout: 20s
YAML

PIN=$(cat "$OUT/pin.txt")
docker rm -f shape-srv shape-cli >/dev/null 2>&1 || true
trap 'docker rm -f shape-srv shape-cli >/dev/null 2>&1 || true' EXIT

# The responder sits on the node's own loopback, which is where the node dials it from — so the
# source it reports is the node's socket for that session and nothing else.
docker run -d --name shape-srv --network "$NET" -v "$W:/w" -w /w "$IMG" \
	sh -c "/w/$OUT/seen -listen 127.0.0.1:9101 & /w/$OUT/seen -listen 127.0.0.1:9102 & exec /w/$OUT/ref-hysteria server -c /w/$OUT/server.yaml" >/dev/null
sleep 2

ask() {
	who=$1
	cmd=$2
	docker rm -f shape-cli >/dev/null 2>&1 || true
	docker run -d --name shape-cli --network "$NET" -v "$W:/w" -w /w "$IMG" sh -c "$cmd" >/dev/null
	sleep 4
	echo "=== $who"
	docker exec shape-cli "/w/$OUT/seen" -probe 127.0.0.1:5301 || {
		echo "  the probe got nothing"; docker logs shape-cli 2>&1 | tail -3
	}
}

# TWO AXES, AND ONLY ONE OF THEM CAN BE DRIVEN HERE.
#
# Varying the SOURCE socket is the axis both clients treat the same way — a session per local socket
# — and it is driven below for both, as the control that the stand measures what it claims to.
#
# Varying the DESTINATION from ONE socket is where the models PARTED until 16 September, and it can
# only be driven through the reference: its forwarder takes a remote per listener, so two listeners
# are two destinations, while this client's fixed form (-u PORT@HOST:PORT) names one. Driving it
# through this client would need its transparent mode, which needs tproxy, and the container kernel
# has no nft_tproxy — `nft ... tproxy ip to ...` comes back "No such file or directory". So the
# reference's half is measured here, and this client's on a router instead, against the
# Internet rather than a stand: tools/natshape asks two STUN servers from ONE socket what source
# they see. Through the live node it answered TWICE, because the client changed between the two —
# one port for both destinations (36660) while a session belonged to the client, and a port each
# (46269 and 37514, then 60103 and 44472) once udp_session_for began keying by the pair, which is
# the reference's model and the maintainer's decision of 16 September.
ask_pair() {
	who=$1
	cmd=$2
	docker rm -f shape-cli >/dev/null 2>&1 || true
	docker run -d --name shape-cli --network "$NET" -v "$W:/w" -w /w "$IMG" sh -c "$cmd" >/dev/null
	sleep 4
	echo "=== $who, one socket to two destinations"
	docker exec shape-cli "/w/$OUT/seen" -pair 127.0.0.1:5301,127.0.0.1:5302 || {
		echo "  the probe got nothing"; docker logs shape-cli 2>&1 | tail -3
	}
}

ask_pair "reference" "exec /w/$OUT/ref-hysteria client -c /w/$OUT/udpcli.yaml"

echo
ask "reference" "exec /w/$OUT/ref-hysteria client -c /w/$OUT/udpcli.yaml"
ask "ours" "exec /w/$OUT/lc/lc-tunnel -H shape-srv 4443 www.avito.ru standpass - 1080 -t 127.0.0.1:9000 -u 5301@127.0.0.1:9101 -p $PIN"

# THE CEILING: a hundred sockets at once, which in either client is a hundred sessions. The
# reference keeps its sessions in a map with no limit (vendor/hysteria/core/client/udp.go:85-103,
# :144-171); this client stopped at thirty-two — per LAN host, and per connection for everything
# together — until 2026-09-25, and answered thirty-two of a hundred. `LC_TUNNEL_MANY` runs another
# build of lc-tunnel for this part only, which is how that was measured.
ask_many() {
	who=$1
	cmd=$2
	docker rm -f shape-cli >/dev/null 2>&1 || true
	docker run -d --name shape-cli --network "$NET" -v "$W:/w" -w /w "$IMG" sh -c "$cmd" >/dev/null
	sleep 4
	echo "=== $who, a hundred sockets at once"
	docker exec shape-cli "/w/$OUT/seen" -many 127.0.0.1:5301,100 || {
		echo "  the probe got nothing"; docker logs shape-cli 2>&1 | tail -3
	}
}

echo
ask_many "reference" "exec /w/$OUT/ref-hysteria client -c /w/$OUT/udpcli.yaml"
ask_many "ours" "exec ${LC_TUNNEL_MANY:-/w/$OUT/lc/lc-tunnel} -H shape-srv 4443 www.avito.ru standpass - 1080 -t 127.0.0.1:9000 -u 5301@127.0.0.1:9101 -p $PIN"
