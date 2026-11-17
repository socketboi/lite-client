#!/bin/sh
# The first flight of the reference client and of ours, recorded by the same quic-go server.
#
# qstand (main.go, next to this file) is a QUIC server built from the REFERENCE library with its own
# qlog tracer, so the record of what a client sent is written by quic-go rather than by us. This
# runs the reference client (hysteria's own, from vendor/hysteria/app) and lc-tunnel against it in
# turn and prints the CRYPTO frames of every Initial packet, in the order the server read them.
#
# That order is the whole point. The client hides the second half of SNI: it ends a CRYPTO frame
# where the name's second half begins, carries on after its end, and sends the withheld piece last,
# in the final Initial packet of the flight — so a DPI that reassembles frames as they arrive reads
# a truncated name. Reading the source settles what quic-go INTENDS; only this settles what the two
# clients actually put on the wire, frame boundary for frame boundary.
#
# Run from the repository root:
#
#	sh tools/vendorcap/qstand/run.sh
#
# Both clients fail to authenticate against this server, and that is fine: the Initial flight is
# complete long before a word of HTTP/3 is spoken.
set -e

IMG=lc-build:local
OUT=build-stand

W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker run -i --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod \
	-w /w "$IMG" sh -s <<SH
set -e
cd /w
mkdir -p $OUT

[ -x $OUT/ref-hysteria ] || (cd vendor/hysteria/app && go build -o /w/$OUT/ref-hysteria .)
[ -f $OUT/cert.pem ] || {
	openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem \
	    -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null
	openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt
}
make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel

# go.mod tidy first, every time: without it the build fails on go.sum, the server never starts, and
# a comparison of two empty captures says the clients agree.
cd tools/vendorcap/qstand && go mod tidy >/dev/null 2>&1 && go build -o /tmp/qstand . && cd /w

cp $OUT/cert.pem /tmp/hc.pem
cp $OUT/key.pem /tmp/hk.pem
rm -rf /tmp/ql /tmp/raw && mkdir -p /tmp/ql /tmp/raw
# QSTAND_RAW keeps each client's first datagrams and writes them out opened: the Initial packets
# frame by frame and the ClientHello byte for byte, as the path sees them (see raw.go).
QSTAND_RAW=/tmp/raw QLOGDIR=/tmp/ql /tmp/qstand 127.0.0.1:14451 >/tmp/qstand.log 2>&1 &
sleep 2

cat > /tmp/refcli.yaml <<YAML
server: 127.0.0.1:14451
auth: standpass
tls:
  sni: www.avito.ru
  insecure: true
socks5:
  listen: 127.0.0.1:1099
YAML

timeout 12 $OUT/ref-hysteria client -c /tmp/refcli.yaml >/dev/null 2>&1 || true
for f in /tmp/ql/*.sqlog; do mv "\$f" /tmp/ql/ref.sqlog; done
for f in /tmp/raw/*.txt; do mv "\$f" /tmp/raw/ref.txt; done

# Ours with the parrot off, as the reference runs with quic.disableChromeParrot.
timeout 12 $OUT/lc/lc-tunnel -H 127.0.0.1 14451 www.avito.ru standpass - 1098 \
	-t 127.0.0.1:9000 -p \$(cat $OUT/pin.txt) -c off >/dev/null 2>&1 || true
for f in /tmp/ql/*.sqlog; do [ "\$f" = /tmp/ql/ref.sqlog ] || mv "\$f" /tmp/ql/ours.sqlog; done
for f in /tmp/raw/*.txt; do [ "\$f" = /tmp/raw/ref.txt ] || mv "\$f" /tmp/raw/ours.txt; done

# And ours as it runs by default: parroting Chrome, as the reference does.
timeout 12 $OUT/lc/lc-tunnel -H 127.0.0.1 14451 www.avito.ru standpass - 1098 \
	-t 127.0.0.1:9000 -p \$(cat $OUT/pin.txt) >/dev/null 2>&1 || true
for f in /tmp/ql/*.sqlog; do case "\$f" in /tmp/ql/ref.sqlog|/tmp/ql/ours.sqlog) ;; *) mv "\$f" /tmp/ql/chrome.sqlog ;; esac; done
for f in /tmp/raw/*.txt; do case "\$f" in /tmp/raw/ref.txt|/tmp/raw/ours.txt) ;; *) mv "\$f" /tmp/raw/chrome.txt ;; esac; done

for who in ref ours chrome; do
	# The count first, and it is not decoration: an Initial packet that pads a datagram it does
	# not lead, or one written for a packet that turns out empty, makes a client send them
	# without end. That reads as thousands of lines below and as one number here.
	echo "=== \$who: \$(tr -d '\r' < /tmp/ql/\$who.sqlog | grep -c '"packet_type":"initial"') Initial packets"
	# And the largest 1RTT packet, which is what Path MTU Discovery bought: the search starts at
	# 1280 and walks up towards the ceiling, so a client that never probes stays at 1280 and one
	# that does shows its probe here.
	echo "    largest 1RTT packet: \$(tr -d '\r' < /tmp/ql/\$who.sqlog | grep '"packet_type":"1RTT"' \
	    | sed -e 's/.*"raw":{"length":\([0-9]*\).*/\1/' | sort -n | tail -1) bytes"
	tr -d '\r' < /tmp/ql/\$who.sqlog | grep packet_received | grep '"initial"' | head -8 \
	    | sed -e 's/.*"packet_number":\([0-9]*\).*"dcil":\([0-9]*\).*"payload_length":\([0-9]*\).*"frames":\[\(.*\)\]}}/Initial \1 (dcid \2 bytes, payload \3): \4/' \
	    | sed -e 's/{"frame_type":"\([a-z_]*\)"/ \1/g' -e 's/[]["{}]//g' -e 's/,/ /g'
done
for who in ref ours chrome; do
	echo "=== \$who, opened"
	cat /tmp/raw/\$who.txt 2>/dev/null || echo "    (nothing captured)"
done
SH
