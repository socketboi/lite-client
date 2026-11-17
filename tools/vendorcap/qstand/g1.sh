#!/bin/sh
# The request and SETTINGS after a Hysteria2 handshake: in one packet, or which came first and how
# far apart — per connection, for the reference client and for ours, as the qstand server's qlog
# records them (see quic/conn.c, qconn_control_goroutine).
#
# Run from the repository root, in the build image:
#
#   docker run --rm -v "$PWD:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod \
#       lc-build:local sh /w/tools/vendorcap/qstand/g1.sh
#
# `-e N=40` for more connections, `-e LC=<path>` for another build of lc-tunnel. One line per
# connection, then a summary per client.
set -e
cd /w
OUT=build-stand; N=${N:-20}
[ -x $OUT/ref-hysteria ] || (cd vendor/hysteria/app && go build -o /w/$OUT/ref-hysteria .)
[ -f $OUT/cert.pem ] || { openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null; openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt; }
[ -n "${LC:-}" ] || { make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel; LC=$OUT/lc/lc-tunnel; }
cd tools/vendorcap/qstand && go mod tidy >/dev/null 2>&1 && go build -o /tmp/qstand . && cd /w
cp $OUT/cert.pem /tmp/hc.pem; cp $OUT/key.pem /tmp/hk.pem
rm -rf /tmp/ql && mkdir -p /tmp/ql
QSTAND_SERVE=1000 QLOGDIR=/tmp/ql /tmp/qstand 127.0.0.1:14451 >/tmp/qstand.log 2>&1 &
sleep 2
printf 'server: 127.0.0.1:14451\nauth: standpass\ntls:\n  sni: www.avito.ru\n  insecure: true\nsocks5:\n  listen: 127.0.0.1:1099\n' > /tmp/refcli.yaml
judge() { # a qlog file: "same", "req first +ms", "ctrl first +ms"
	tr -d '\r' < "$1" | grep packet_received | grep '"1RTT"' | awk '
	{ t = $0; sub(/.*"time":/, "", t); sub(/[,}].*/, "", t)
	  r = index($0, "\"stream_id\":0,") || index($0, "\"stream_id\":0}"); c = index($0, "\"stream_id\":2,") || index($0, "\"stream_id\":2}")
	  if (r && rt == "") rt = t; if (c && ct == "") ct = t
	  if (r && c && same == "") same = 1 }
	END { if (rt == "" || ct == "") { print "missing"; exit }
	      if (same && rt == ct) print "same"; else if (rt+0 < ct+0) printf "req first +%.2f ms\n", ct-rt; else printf "ctrl first +%.2f ms\n", rt-ct }'
}
run() { # who, command
	who=$1; shift
	for i in $(seq 1 $N); do
		rm -f /tmp/ql/*.sqlog
		timeout 3 "$@" >/dev/null 2>&1 || true
		f=$(ls /tmp/ql/*.sqlog 2>/dev/null | head -1)
		[ -n "$f" ] && echo "$who $(judge $f)" || echo "$who noqlog"
	done
}
{
run ref $OUT/ref-hysteria client -c /tmp/refcli.yaml
run lc $LC -H 127.0.0.1 14451 www.avito.ru standpass - 1098 -t 127.0.0.1:9000 -p $(cat $OUT/pin.txt)
} > /tmp/g1.lines
cat /tmp/g1.lines
echo "== summary"
awk '{k=$1" "$2" "$3; if ($2=="same"||$2=="missing"||$2=="noqlog") k=$1" "$2; c[k]++
      if ($4 ~ /^\+/) {v=substr($4,2)+0; s[k]+=v; if (!(k in mn) || v<mn[k]) mn[k]=v; if (v>mx[k]) mx[k]=v}}
     END {for (k in c) printf "%-18s %3d  %s\n", k, c[k], (k in s) ? sprintf("%.2f..%.2f ms, mean %.2f", mn[k], mx[k], s[k]/c[k]) : ""}' /tmp/g1.lines | sort
