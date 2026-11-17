#!/bin/sh
# The resolver stand: Go's own resolver (the references', CGO_ENABLED=0) and lite-client's
# transcription of it (src/net/goresolve.c) look up the same names against the same DNS server, under
# the same /etc/resolv.conf, /etc/nsswitch.conf and /etc/hosts, scenario by scenario. The server
# (stub/main.go) logs every query it receives; a scenario is the same when both logs are the same —
# the queries, their transport, server, name, type, flags and EDNS record, in the same half-second
# windows — and both lookups end the same way: the same addresses in the same order, or both an
# error. The error's words are printed beside it; they go to a log line and nowhere else.
#
# Run from the repository root, in the build image, as root (it rewrites /etc/resolv.conf,
# /etc/nsswitch.conf and /etc/hosts of the container it runs in, and listens on port 53):
#
#   docker run --rm -v "$PWD:/w" lc-build:local sh /w/tools/vendorcap/dnsstand/run.sh
#
# `-e SCENARIOS="basic nx"` runs only those; `-e OURS=/path` runs another build of the tool — a mutant.
set -u
LC=/w
HERE=$LC/tools/vendorcap/dnsstand
W=/tmp/dnsstand; rm -rf $W; mkdir -p $W/stub/dnsmessage
export PATH=/usr/local/go1.27/bin:$PATH
GOROOT_VENDOR=$(go env GOROOT)/src/vendor/golang.org/x/net/dns/dnsmessage

# The stub, with GOROOT's own copy of dnsmessage beside it; the reference client; our tool.
cp $HERE/stub/main.go $W/stub/
cp $GOROOT_VENDOR/*.go $W/stub/dnsmessage/ && rm -f $W/stub/dnsmessage/*_test.go
printf 'module dnsstand\n\ngo 1.27\n' > $W/stub/go.mod
(cd $W/stub && go build -o $W/stub.bin .) || exit 1
mkdir -p $W/ref && cp $HERE/ref/main.go $W/ref/ && printf 'module ref\n\ngo 1.27\n' > $W/ref/go.mod
(cd $W/ref && CGO_ENABLED=0 go build -o $W/ref.bin .) || exit 1
if [ -n "${OURS:-}" ]; then
    cp "$OURS" $W/ours.bin
else
    cc -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -I$LC/src -o $W/ours.bin $HERE/ours.c \
        $LC/src/net/goresolve.c $LC/src/core/netip.c $LC/src/core/goquote.c $LC/src/core/rnd.c -lpthread || exit 1
fi

cp /etc/resolv.conf $W/resolv.saved 2>/dev/null
cp /etc/hosts $W/hosts.saved 2>/dev/null
cp /etc/nsswitch.conf $W/nss.saved 2>/dev/null

# scenario NAME LOOKUP  (RESOLV, HOSTS, NSS and RULES are set before the call; NSS "-" removes it)
bad=0
results=""
run_one() { # who bin name
    who=$1 bin=$2 name=$3
    printf '%s\n' "$RULES" > $W/rules
    printf '%s\n' "$RESOLV" > /etc/resolv.conf
    printf '%s\n' "$HOSTS" > /etc/hosts
    if [ "$NSS" = "-" ]; then rm -f /etc/nsswitch.conf; else printf '%s\n' "$NSS" > /etc/nsswitch.conf; fi
    $W/stub.bin $W/rules $W/$who.log 127.0.0.1:53 127.0.0.2:53 &
    sp=$!
    sleep 0.3
    timeout 60 $bin "$name" > $W/$who.out 2>&1
    sleep 0.3
    kill $sp 2>/dev/null; wait $sp 2>/dev/null
    # windows of half a second, sorted inside each; with ANYTYPE the query type is left out — see rotate
    awk -v anytype="${ANYTYPE:-0}" '{ w = int(($1 + 250) / 500); $1 = w; if (anytype == 1) $5 = "-"; print }' \
        $W/$who.log | sort > $W/$who.norm
}
scenario() {
    sc=$1 name=$2
    case " ${SCENARIOS:-$sc} " in *" $sc "*) ;; *) return ;; esac
    run_one ref $W/ref.bin "$name"
    run_one ours $W/ours.bin "$name"
    ro=$(cat $W/ref.out); oo=$(cat $W/ours.out)
    same_log=0; cmp -s $W/ref.norm $W/ours.norm && same_log=1
    same_out=0
    if [ "$ro" = "$oo" ]; then same_out=1
    else case "$ro" in ERR*) case "$oo" in ERR*) same_out=1 ;; esac ;; esac
    fi
    if [ $same_log = 1 ] && [ $same_out = 1 ]; then v=same; else v=DIFF; bad=1; fi
    printf '%-12s %s\n' "$sc" "$v"
    printf '    ref  %s\n    ours %s\n' "$ro" "$oo"
    if [ $same_log = 0 ]; then
        echo "    queries (ref | ours):"
        diff $W/ref.norm $W/ours.norm | sed 's/^/      /' | head -20
    fi
}

S1="nameserver 127.0.0.1"
S2="nameserver 127.0.0.1
nameserver 127.0.0.2"
NSS=-
HOSTS="127.0.0.1 localhost"

RESOLV="$S1"; RULES="* * * a 192.0.2.1 192.0.2.2 2001:db8::1"
scenario basic node.example
RULES="* * A a 192.0.2.7
* * AAAA empty"
scenario v4only node.example
RESOLV="$S2"; RULES="127.0.0.1 * * nx"
scenario nx node.example
RULES="127.0.0.1 * * servfail
127.0.0.2 * * a 192.0.2.3"
scenario servfail node.example
RULES="127.0.0.1 * * lame
127.0.0.2 * * a 192.0.2.4"
scenario lame node.example
RULES="127.0.0.1 * * extnx
127.0.0.2 * * a 192.0.2.5"
scenario extrcode node.example
RESOLV="$S1"; RULES="* * * tc 192.0.2.6 2001:db8::6"
scenario truncated node.example
RESOLV="$S2
options timeout:1 attempts:2"; RULES="127.0.0.1 * * drop
127.0.0.2 * * a 192.0.2.8"
scenario timeout node.example
RESOLV="$S1"; RULES="* * * badid 192.0.2.9"
scenario badid node.example
RULES="* * * wrongq 192.0.2.10"
scenario wrongq node.example
RULES="* * * twoq 192.0.2.11"
scenario twoq node.example
RULES="* * * shortA 192.0.2.12"
scenario shorta node.example
RULES="* * * garbage 192.0.2.13"
scenario garbage node.example
RULES="* * A onlyaaaa 2001:db8::14
* * AAAA empty"
scenario typemismatch node.example
RULES="* * * cname real.example. 192.0.2.15 2001:db8::15"
scenario cname alias.example
RESOLV="$S1
search a.test b.test
options ndots:1"; RULES="* host.b.test. * a 192.0.2.16
* * * nx"
scenario search host
RESOLV="$S1
search a.test
options ndots:3"; RULES="* x.y.a.test. * a 192.0.2.17
* * * nx"
scenario ndots x.y
RESOLV="$S1
search a.test
options ndots:1"; RULES="* x.y.a.test. * a 192.0.2.24
* * * nx"
scenario ndotseq x.y
# Which of the two queries takes which server under rotate is a race between the reference's two
# goroutines: the AAAA one, created last, usually runs first and takes the first offset — eight runs of
# eight when it was first measured — but not every time. What is held is that the two go to the two
# servers, and everything else about them.
RESOLV="$S2
options rotate"; RULES="* * * a 192.0.2.18"
ANYTYPE=1 scenario rotate node.example
ANYTYPE=0
RESOLV="$S1
options single-request"; RULES="* * * a 192.0.2.19 2001:db8::19"
scenario single node.example
RESOLV="$S1
options use-vc"; RULES="* * * a 192.0.2.20"
scenario usevc node.example
RESOLV="$S1
options trust-ad"; RULES="* * * a 192.0.2.21"
scenario trustad node.example
RESOLV="$S1"; HOSTS="127.0.0.1 localhost
192.0.2.22 Node.Example node
2001:db8::22 node.example
192.0.2.23 node.example"; RULES="* * * a 198.51.100.1"
scenario hosts node.example
HOSTS="127.0.0.1 localhost"; NSS="hosts: dns files"; RULES="* * * nx"
scenario nssdns localhost
NSS="hosts: files"; RULES="* * * a 198.51.100.2"
scenario nssfiles node.example
NSS=-; RULES="* * * a 198.51.100.3"
scenario onion secret.onion
scenario badname "bad..name"
RESOLV="# nothing"; RULES="* * * a 198.51.100.4"
scenario noservers node.example
RESOLV="$S1"; RULES="* * * a 192.0.2.30 192.0.2.31 10.0.0.1 127.0.0.2 2001:db8::30 ::1 fe80::1"
scenario sort node.example

cp $W/resolv.saved /etc/resolv.conf 2>/dev/null
cp $W/hosts.saved /etc/hosts 2>/dev/null
cp $W/nss.saved /etc/nsswitch.conf 2>/dev/null
exit $bad
