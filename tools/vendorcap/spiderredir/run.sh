#!/bin/sh
# The eleventh stand: what the spider sends when the site it fetches answers with a redirect.
#
# When REALITY does not authenticate the node, the reference fetches the site the node pretends to
# be with an http.Client over x/net's http2.Transport on the same connection
# (vendor/Xray-core/transport/internet/reality/reality.go:210-277). That client follows redirects:
# up to ten, each a new request built from the first one's headers with a Referer, a Cookie that
# stays only on the same domain, the previous answer read to 2 KiB and closed — and a redirect to
# another host is a NEW HTTP/2 connection, which x/net dials through a function that hands it the
# same TLS connection back, so a second connection preface goes out in the middle of the stream.
# Real sites redirect "/" as a matter of course, so this is the spider's ordinary path, not an edge.
#
# Both clients are pointed at a node with the wrong public key, so both take the stranger path, and
# the site behind the node (dest/) answers each scenario with a redirect and prints everything the
# client sent on that connection, frame by frame, header lists in order:
#
#   rel abs dots schemeless   a relative Location, an absolute one on the same host, one with dot
#                             segments and a fragment, one without a scheme
#   chain                     a redirect to another redirect, forever — the client stops at ten
#   cross sub                 another host; a subdomain of this one — both a new connection
#   http                      https to http — x/net refuses the scheme
#   noloc                     a 302 with no Location — the answer itself is the page
#   smallbody bigbody         a redirect whose body is 1000 bytes, and 5000 — slurped or not
#   see                       303
#   gzbody gzsmall            a gzip body of 31 KB, and one of 300 bytes inflated — read through gzip.Reader
#   latebody latebig          1000 bytes and 5000 that come 300 ms after the answer
#   closeafter                a page of twenty links, and the site closes the connection the moment
#                             it has sent the frame that ends it: the page is still harvested, and
#                             the next connection's first :path is one of the links (reality.go:263-275).
#                             Last in the list: what it harvests is what every later first request
#                             draws from.
#
# Run from the repository root, in the build image with the network on, after `make build/lc-tunnel`:
#
#   docker run --rm -v "$PWD:/repo" lc-build:local sh /repo/tools/vendorcap/spiderredir/run.sh
#
# `-e LC_TUNNEL=…` runs another build of lc-tunnel; `-e SCENARIOS="rel chain"` runs only those.
# `-e DEST_TIMING=1` adds, under each connection, every read and write the site made, in microseconds
# from the end of its handshake, timestamped at I/O return before capture locking/parsing,
# with the frames each completed — how long the client took to its
# first request, and what it had seen when it acknowledged, cancelled or asked again (the spider's
# clock in cmd/lc-tunnel/main.c was set from these, 1 October).
# Logs mark this clock as io-return-v2; capture+ records observation overhead separately.
# `-e CLIENT_ORDER="lc:19991 ref:19990"` reverses the paired order for counterbalanced runs.
# `-e SAMPLE_REPEATS=N` repeats each scenario's paired probe N times (1-20, default 1).
# With repeats, destination logs identify each probe group; retry connections stay grouped.
# `-e DEST_TLS12=1` serves the site over TLS 1.2 only, as mail.ru did on 2026-08-18 (T3). 29 September:
# over TLS 1.2 the first connection of rel, chain, smallbody and closeafter carried the same frames
# from both clients, sizes included (464, 44, 42).
#
# ⚠️ HEADER ORDER IS A DRAW, for both clients: x/net writes the header map in Go's iteration order,
# which is random per map (see reality/spider.c and core/gomap.c). Compare the SETS and the pseudo-
# header order, and read two runs before calling an order a difference.
#
# WHAT THE REFERENCE DID, 24 September (Xray built from vendor/ with go1.26.6, x/net v0.57.0):
#
#   rel abs dots schemeless see smallbody   one more HEADERS on the same connection, stream 3: the
#       first request's fifteen headers and a referer of the previous URL, walked as a fresh map;
#       its header block 44 bytes against the first one's 464 — the encoder's dynamic table at work.
#       dots: "x/../y/./z?k=v#frag" asked for as /y/z?k=v.
#   chain        ten requests in all — /, /c1 … /c9, streams 1 to 19 — and no eleventh
#   bigbody      WINDOW_UPDATE on the connection for the 5000 bytes it never read, then stream 3;
#                smallbody reads its 1000 and returns nothing
#   cross sub    a SECOND PREFACE, SETTINGS and WINDOW_UPDATE mid-stream, then HEADERS on stream 1
#                again from a fresh encoder (477 bytes); cross without the cookie, sub with it. The
#                site's server reads the first nine bytes of that preface as a frame header and
#                drops the connection — the dest here holds its close half a second to see the rest
#   http noloc   nothing after the first request
#
#   gzbody       five WINDOW_UPDATE pairs of 4096 — bufio's fills, read to where flate's window fills — then
#                +10978 for the rest, then stream 3; RST_STREAM(CANCEL) on none to two connections in six
#   gzsmall latebody   stream 3 and nothing else; latebig   RST_STREAM(CANCEL), then stream 3
#   closeafter   (27 September, v26.9.9) the connections after the first ask for a harvested link —
#                /h8 /h6 /h7 /h8. This client asked for / on every one until the same day: the page and
#                the close came in one read, and the read's failure ended the fetch before the page
#                was settled (spider_lost in cmd/lc-tunnel/main.c); since, /h12 /h9 /h0 /h15.
#
# and this client, before it followed redirects: nothing after the first request, in every one; since
# 24 September (reality/fetch.c) the same bytes as the reference on every connection of every
# scenario, the Chrome version each process draws aside — except gzbody's cancel, which this client
# sent on every connection. Since the second fetch (24 September, later: Go's gzip reader in
# core/gozip, the socket read dry before Do acts) not that either: the same bytes on every
# connection of every scenario, gzbody's cancel on none in either, bigbody's a race in both (one and
# three in six). See tools/vendorcap/README.md, the eleventh stand.
#
# ⚠️ EVERY REQUEST DIALS SEVERAL TIMES. A client whose dial fails dials again, and every dial to this
# node is a stranger's, so one scenario shows as several connections from each client, each with its
# own spider. The dest closes a connection three seconds after it goes quiet — neither client would —
# and prints it then.
set -u
CLIENT_ORDER=${CLIENT_ORDER:-"ref:19990 lc:19991"}
case "$CLIENT_ORDER" in
    "ref:19990 lc:19991"|"lc:19991 ref:19990") ;;
    *) echo "CLIENT_ORDER must contain each stand client once" >&2; exit 1 ;;
esac
SAMPLE_REPEATS=${SAMPLE_REPEATS:-1}
case "$SAMPLE_REPEATS" in
    [1-9]|1[0-9]|20) ;;
    *) echo "SAMPLE_REPEATS must be an integer from 1 to 20" >&2; exit 1 ;;
esac
LC=$(cd "$(dirname "$0")/../../.." && pwd)   # the repository root, wherever it is mounted
HERE=$LC/tools/vendorcap/spiderredir
W=/tmp/spiderredir; rm -rf $W; mkdir -p $W; cd $W

# The Go the reference's release is built with: its go.mod names it (v26.10.31: 1.27), and under
# GOTOOLCHAIN=local the image's default 1.26 refuses the module outright.
XGO=go
grep -q '^go 1.27' $LC/vendor/Xray-core/go.mod && XGO=/usr/local/go1.27/bin/go
(cd $LC/vendor/Xray-core && $XGO build -o $W/xray ./main) > $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
# Keep the controlled destination on its independent x/net v0.58.0 fixture pin.
# It is a test server, not the client's HTTP/2 reference; use the committed sums.
cp -r $HERE/dest $W/destsrc &&
	(cd $W/destsrc && $XGO build -mod=readonly -o $W/dest.bin .) >> $W/build.log 2>&1 ||
	{ tail -3 $W/build.log; exit 1; }
(cd $LC/tools/vendorcap/wireshape/probe && go build -o $W/probe.bin .) >> $W/build.log 2>&1 || { tail -3 $W/build.log; exit 1; }
TUN=${LC_TUNNEL:-$LC/build/lc-tunnel}
[ -x "$TUN" ] || { echo "NO $TUN: make build/lc-tunnel first"; exit 1; }
cp "$TUN" $W/lc-tunnel

# TWO KEYPAIRS: the node holds the first, both clients are told the second — see spiderlife.
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

# The stand's own authority, handed to both clients through SSL_CERT_FILE — see spiderlife.
openssl req -x509 -newkey rsa:2048 -nodes -keyout $W/ca.key -out $W/ca.pem -days 2 \
    -subj "/CN=spiderredir stand CA" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout $W/leaf.key -out $W/leaf.csr \
    -subj "/CN=stand.example" 2>/dev/null
{ echo "subjectAltName=DNS:stand.example"; echo "extendedKeyUsage=serverAuth"; } > $W/leaf.ext
openssl x509 -req -in $W/leaf.csr -CA $W/ca.pem -CAkey $W/ca.key -CAcreateserial \
    -out $W/leaf.pem -days 2 -extfile $W/leaf.ext 2>/dev/null

echo "warm none" > $W/scenario
$W/dest.bin $W/leaf.pem $W/leaf.key $W/scenario > $W/dest.log 2>&1 &
$W/xray run -c $W/server.json > $W/server.log 2>&1 &
sleep 2
export SSL_CERT_FILE=$W/ca.pem
$W/xray run -c $W/client.json > $W/client.log 2>&1 &
$W/lc-tunnel $LC/package/files/fingerprint.fpt 127.0.0.1 14480 stand.example "$wrong" 0123abcd \
    $UUID 19991 -t 127.0.0.1:18080 -f xtls-rprx-vision -w 1 > $W/tun.log 2>&1 &
sleep 3

SCENARIOS=${SCENARIOS:-"rel abs dots schemeless chain cross sub http noloc smallbody bigbody see gzbody gzsmall latebody latebig closeafter"}
for sc in $SCENARIOS; do
    sample=1
    while [ "$sample" -le "$SAMPLE_REPEATS" ]; do
    for who in $CLIENT_ORDER; do
        n=${who%%:*}; p=${who#*:}
        if [ "$SAMPLE_REPEATS" -eq 1 ]; then
            echo "$n $sc" > $W/scenario
        else
            echo "$n $sc $sample" > $W/scenario
        fi
        printf 'PROBE_START role=%s scenario=%s sample=%s/%s\n' "$n" "$sc" "$sample" "$SAMPLE_REPEATS"
        $W/probe.bin tcp 127.0.0.1:$p > /dev/null 2>&1
        sleep 6
        printf 'PROBE_COMPLETE role=%s scenario=%s sample=%s/%s\n' "$n" "$sc" "$sample" "$SAMPLE_REPEATS"
    done
    sample=$((sample + 1))
    done
done
sleep 4

for p in /proc/[0-9]*; do
    case "$(tr '\0' ' ' < $p/cmdline 2>/dev/null)" in
        "$W"/*) kill "${p#/proc/}" 2>/dev/null ;;
    esac
done
wait

# Each connection's account, grouped by scenario and client. A connection that sent nothing — the
# node's own look at the target, a dial the client gave up — is left out.
for sc in $SCENARIOS; do
    for n in ref lc; do
        printf '\n==== %s %s\n' "$sc" "$n"
        awk -v want="$n $sc" '
            /^[a-z?]+ [a-z]+ \| [0-9]+ bytes$/ { keep = (($1 " " $2) == want) && $4 != "0"; if (keep) conns++ }
            keep { print }
            END { if (!conns) print "  (no connection sent anything)" }' $W/dest.log
    done
done

# AND SIDE BY SIDE: each client's first connection per scenario, frames only — what to read first.
# The header order inside a block is a draw (see the top), so only the pseudo-headers, the referer
# and whether a cookie went are shown.
printf '\n==== skeleton: first connection of each client, per scenario\n'
for sc in $SCENARIOS; do
    for n in ref lc; do
        awk -v want="$n $sc" '
            /^[a-z?]+ [a-z]+ \| [0-9]+ bytes$/ { if (keep) exit; keep = (($1 " " $2) == want) && $4 != "0"; if (keep) print; next }
            !keep { next }
            /^  PREFACE/ { print; next }
            /^  \[[0-9]+\]/ { line = $0; sub(/ order=.*/, "", line)
                             if ($0 ~ /HEADERS/) line = line (($0 ~ /,cookie,|,cookie$|order=cookie,/) ? " +cookie" : " -cookie")
                             print line; next }
            /^    (:path|:authority|referer): / { print }' $W/dest.log
    done
done
