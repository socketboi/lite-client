#!/bin/sh
# The eighth stand: how long a connection lives after REALITY says "this is not our node".
#
# WHAT IS BEING ASKED. When verification fails, the reference does not close the connection — it
# hands it to a goroutine that fetches the site the node was pretending to be, and says so in a
# comment of its own: `// Do not close the connection`
# (vendor/Xray-core/transport/internet/reality/reality.go:210-299). Nothing in that path ever
# closes the socket; it ends when the far end ends it or when the process does. This client cannot
# do that — a session in ST_SPIDER holds a descriptor and nothing would ever free it — so it bounds
# the fetch with SPIDER_MS, three seconds, and closes. That bound is OURS, and a bound the reference
# does not have is a shape on the wire: a path watching both sees one client close first, always at
# the same interval, and the other never close at all.
#
# So the number is measured instead of argued: both clients are pointed at a node with the WRONG
# public key, which is exactly what makes a node answer as a stranger, and every socket either of
# them opens towards that node is followed from connect to close under strace.
#
# WHAT IT FOUND, 16 September, with a 40 s watch:
#
#   reference   5 connections towards the node, ALL FIVE STILL OPEN when the watch ended
#   ours        5 connections, each closed 0.01-0.02 s after it was opened
#
# Two things, and the second was not the one this stand was built to look for.
#
#   - The bound is not where its own comment says it is. SPIDER_MS is three seconds, and no session
#     came near it: the fetch ends at END_STREAM and the session ends with it, so the real number is
#     ten to twenty milliseconds against a reference that never closes at all.
#
#     CLOSED the same day by decision of the maintainer: the session is given no clock and lives until
#     the far end ends it, and the frames that keep a connection alive — SETTINGS and PING — are now
#     answered, because a session that lives that long is one a site pings. The stand then read all
#     five of ours STILL OPEN beside all five of the reference's.
#   - THE PATH IS NOT ALWAYS SpiderX. The reference asked for `/`, then `/two`, `/two`, `/three`,
#     `/` — its `maps` is package-level, so hrefs harvested from the first page are the pool every
#     LATER connection draws its first path from (reality.go:220-231, :269-275). Ours asked for `/`
#     five times. That is reachable at the default configuration — not through SpiderY, which is all
#     zeros and therefore one fetch per connection, but through the SECOND connection, and a node
#     that answers as a stranger gets five of those from one request.
#
#     CLOSED the same day (src/reality/paths.c): the body is scanned as it passes, the hrefs go into
#     a set the whole process shares, and the path is drawn from it. The stand then read `/`, `/`,
#     `/`, `/one`, `/one` from this client against `/`, `/two`, `/three`, `/one`, `/one` from the
#     reference — the same behaviour, differing only in which way the draws fell.
#
# WHY THE DEST HERE NEVER CLOSES. tools/vendorcap/spiderlife/dest keeps its connections alive and
# sets no idle timeout, unlike the wireshape stand's target. A close in the trace can then only be
# the client's own — which is the measurement. A real site would close on its own schedule and the
# answer would be about that site.
#
# Run from the repository root, in the build image:
#
#   docker run --rm -v "$PWD:/repo" lc-build:local sh /repo/tools/vendorcap/spiderlife/run.sh
#
# after `make build/lc-tunnel`.
set -u
LC=$(cd "$(dirname "$0")/../../.." && pwd)   # the repository root, wherever it is mounted
HERE=$LC/tools/vendorcap/spiderlife
W=/tmp/spiderlife; rm -rf $W; mkdir -p $W; cd $W
WATCH=${WATCH:-60}

(apt-get update && apt-get install -y strace) >/dev/null 2>&1 || { echo "NO STRACE"; exit 1; }
(cd $LC/vendor/Xray-core && go build -o $W/xray ./main) > $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
(cd $HERE/dest && go build -o $W/dest.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
(cd $LC/tools/vendorcap/wireshape/probe && go build -o $W/probe.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
[ -x $LC/build/lc-tunnel ] || { echo "NO build/lc-tunnel: make build/lc-tunnel first"; exit 1; }

# TWO KEYPAIRS. The node holds the first; both clients are told the second, so neither can
# authenticate the node and both take the stranger path — the one under measurement.
keys=$($W/xray x25519)
priv=$(printf '%s\n' "$keys" | awk -F': *' '/Private/{print $2; exit}')
other=$($W/xray x25519)
wrong=$(printf '%s\n' "$other" | awk -F': *' '/Password|Public/{print $2; exit}')
UUID=00000000-0000-4000-8000-000000000001

cat > $W/server.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":14480,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"127.0.0.1:18444","serverNames":["stand.example"],"privateKey":"$priv","shortIds":["0123abcd"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}
JSON
cat > $W/client.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":19990,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":18080,"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":14480,"users":[{"id":"$UUID","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"stand.example","fingerprint":"firefox","publicKey":"$wrong","password":"$wrong","shortId":"0123abcd"}}}]}
JSON

# THE STAND CARRIES ITS OWN AUTHORITY. Both clients verify the real certificate when REALITY
# does not authenticate the node, so a self-signed dest ends both handshakes with
# bad_certificate and no spider ever runs — the first version of this stand measured exactly
# that and reported nothing. The CA is handed to both through SSL_CERT_FILE, which is where
# Go looks first and, because ours copies that search, where this client looks first too
# (src/cert/chain.c).
openssl req -x509 -newkey rsa:2048 -nodes -keyout $W/ca.key -out $W/ca.pem -days 2 \
    -subj "/CN=spiderlife stand CA" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout $W/leaf.key -out $W/leaf.csr \
    -subj "/CN=stand.example" 2>/dev/null
{ echo "subjectAltName=DNS:stand.example"; echo "extendedKeyUsage=serverAuth"; } > $W/leaf.ext
openssl x509 -req -in $W/leaf.csr -CA $W/ca.pem -CAkey $W/ca.key -CAcreateserial \
    -out $W/leaf.pem -days 2 -extfile $W/leaf.ext 2>/dev/null

$W/dest.bin $W/leaf.pem $W/leaf.key > $W/dest.log 2>&1 &
$W/xray run -c $W/server.json > $W/server.log 2>&1 &
sleep 2

TRACE="strace -f -tt -yy -s 0 -e trace=connect,close,shutdown"
export SSL_CERT_FILE=$W/ca.pem
$TRACE -o $W/ref.strace $W/xray run -c $W/client.json > $W/client.log 2>&1 &
$TRACE -o $W/lc.strace $LC/build/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14480 stand.example "$wrong" 0123abcd \
    $UUID 19991 -t 127.0.0.1:18080 -f xtls-rprx-vision -w 1 > $W/tun.log 2>&1 &
sleep 3

# One request each, and then nothing but waiting: what is measured is what the clients do with the
# sockets afterwards, with nobody asking them for anything.
# The probe from the wireshape stand, because this image has no nc: one TCP request each, which is
# all it takes to make a client dial the node. The two are driven ONE AFTER THE OTHER, with the
# moment of handover recorded, because that is what attributes a fetch at the dest to the client
# that made it: both send the same anchored Chrome User-Agent, so headers cannot.
$W/probe.bin tcp 127.0.0.1:19990 >/dev/null 2>&1
sleep 5
HANDOVER=$(date +%H:%M:%S.%N | cut -c1-12)
$W/probe.bin tcp 127.0.0.1:19991 >/dev/null 2>&1
echo "waiting ${WATCH}s with nobody asking for anything..."
sleep "$WATCH"
kill %3 %4 2>/dev/null
sleep 1
# Every socket towards the node, from connect to close.
#
# Connect and close have to be matched differently: strace annotates a descriptor with BOTH endpoints
# only once it is connected (-yy), so at connect time the node is named by the sockaddr argument and
# afterwards by the annotation. Descriptors are reused, so a connection is a numbered entry and the
# descriptor only says which entry a close belongs to.
report() {
	name=$1
	file=$2
	awk -v name="$name" -v watch="$WATCH" '
		function secs(t,   f) { split(t, f, ":"); return f[1]*3600 + f[2]*60 + f[3] }
		function fdof(line,   s) {
			if (match(line, /(connect|close|shutdown)\([0-9]+/) == 0) return ""
			s = substr(line, RSTART, RLENGTH); sub(/^[a-z]+\(/, "", s); return s
		}
		/connect\(/ && /htons\(14480\)/ {
			fd = fdof($0); if (fd == "") next
			no++; at[no] = secs($2); who[no] = fd; live[fd] = no
		}
		/14480\]>/ && /close\(/ {
			fd = fdof($0); if (fd in live) { closed[live[fd]] = secs($2); delete live[fd] }
		}
		/14480\]>/ && /shutdown\(/ {
			fd = fdof($0); if (fd in live) shut[live[fd]] = secs($2)
		}
		END {
			printf "== %s: %d connections towards the node\n", name, no
			for (i = 1; i <= no; i++) {
				if (i in closed)
					printf "   #%d (fd %s) closed after %6.2f s%s\n", i, who[i], closed[i] - at[i], \
						(i in shut) ? sprintf("  (shutdown at %.2f s)", shut[i] - at[i]) : ""
				else
					printf "   #%d (fd %s) STILL OPEN after the %s s watch\n", i, who[i], watch
			}
		}' "$file"
}
report reference $W/ref.strace
report ours $W/lc.strace

echo
echo "== what each client said about the node"
grep -ci "received real certificate" $W/client.log | sed 's/^/   reference said it received a real certificate /;s/$/ times/'
grep -ci "not authenticated" $W/tun.log | sed 's/^/   ours said the node is not authenticated /;s/$/ times/'
echo "== what the dest was asked for, split at the handover ($HANDOVER)"
awk -v cut="$HANDOVER" '/^dest:/ {
	who = ($2 < cut) ? "reference" : "ours"
	n[who]++
	printf "   %-10s %s %s\n", who, $2, $5
} END { printf "   %d fetches by the reference, %d by ours\n", n["reference"], n["ours"] }' $W/dest.log
