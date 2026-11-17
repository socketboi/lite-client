#!/bin/sh
# The nft ruleset the init script builds, rendered and read.
#
# WHY THIS EXISTS. `check-shell` parses package/files/lite-client.init and says so honestly: "Parsing
# is not running, and this makes no claim to be." So a hundred and forty lines that decide which of a
# household's packets are diverted, and which go straight out to the internet, were held by a syntax
# check and nothing else. The failures that matter here do not look like syntax:
#
#   - the node's own exemption landing AFTER the client rules, so the tunnel's connection to the node
#     matches an intercept rule and is fed back into the tunnel — one request became forty-two round
#     trips the last time that happened;
#   - `ip6 daddr` carrying an IPv4 address, which nft refuses and which therefore cancels the WHOLE
#     atomic ruleset, leaving nothing up while the log says the tunnel started;
#   - a client entry that is not an address, which used to be applied rule by rule until it failed,
#     leaving the hosts listed BEFORE it with 80 and 443 diverted into nothing;
#   - a port creeping into the diverted set. 53 in particular: DNS is the router's own resolver's,
#     and diverting it takes name resolution down with the tunnel.
#
# Every one of those renders as valid shell and valid-looking nft.
#
# HOW. The real function is CUT OUT of the real file and evaluated here, rather than a copy of it
# living in this directory. A copy is the one arrangement guaranteed to keep passing after the
# original changes. The extraction is deliberately dull — grep for the opening line, awk for the next
# `}` at column zero — because it has to work in busybox awk, where a brace in a regex is read as the
# start of an interval and not as a literal.
#
# `nft` is replaced by a shell function that keeps its stdin, so nothing is applied and the ruleset
# can simply be read. That also makes "nft was never called" an assertion in its own right, which is
# how the fail-closed cases below are checked: refusing must mean nothing reached the kernel.
set -u

INIT=package/files/lite-client.init
fails=0

ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

[ -f "$INIT" ] || { bad "$INIT not found — the rules were NOT checked"; exit 1; }

# Cut one shell function out of the init script by name.
extract() {
    _s=$(grep -n "^$1() {" "$INIT" | head -1 | cut -d: -f1)
    if [ -z "$_s" ]; then
        bad "could not find $1() in $INIT — the rules were NOT checked"
        exit 1
    fi
    _e=$(awk -v s="$_s" 'NR>s && $0=="}" {print NR; exit}' "$INIT")
    if [ -z "$_e" ]; then
        bad "could not find the end of $1() — the rules were NOT checked"
        exit 1
    fi
    awk -v s="$_s" -v e="$_e" 'NR>=s && NR<=e' "$INIT"
}

# The validator comes along rather than being stubbed: whether an entry is refused is half of what is
# being checked here, and a stub would be this file's opinion of the answer instead of the script's.
eval "$(extract lc_is_number)"
eval "$(extract lc_is_ip4)"
eval "$(extract lc_is_ip6)"
eval "$(extract lc_clients_ok)"
eval "$(extract lc_node_addrs)"
eval "$(extract lc_rules_up)"

FWMARK=0x1000000
RT_TABLE=104
CONF=/etc/config/lite-client

RULES=""
DOWN_CALLED=0
NFT_CALLED=0

# ⚠️ THROUGH FILES, NOT VARIABLES. The init script applies the ruleset with `echo "$script" | nft -f -`,
# and the right-hand side of a pipeline runs in a SUBSHELL — so a stub that assigned to RULES and a
# counter recorded them where nobody could read them, and every assertion about the rendered text
# then failed while the render itself had worked perfectly.
NFT_OUT=${TMPDIR:-/tmp}/lc-rules.$$
NFT_CNT=${TMPDIR:-/tmp}/lc-rules-count.$$
trap "rm -f \"$NFT_OUT\" \"$NFT_CNT\"" EXIT
# Only the `-f -` form reads stdin. The teardown calls `nft delete table ...` with no input at all,
# and a stub that always ran `cat` would sit there reading the test's own stdin instead.
NFT_ARGS=""
# shellcheck disable=SC2317
nft() {
    case "$*" in
    "-f -") cat > "$NFT_OUT"; echo . >> "$NFT_CNT" ;;
    *) NFT_ARGS="$NFT_ARGS
$*" ;;
    esac
}
# shellcheck disable=SC2317
logger() { :; }
# busybox nslookup, answering in the shape read off an MT7621 router 2026-09-29: the server it
# asked on top, with a tab and a port that are not the node's, then a block per family.
# shellcheck disable=SC2317
nslookup() {
    printf 'Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\n'
    case "$1" in
    node.example.com)
        printf 'Non-authoritative answer:\nName:\tnode.example.com\nAddress: 203.0.113.7\n'
        printf 'Name:\tnode.example.com\nAddress: 203.0.113.8\n\n'
        printf 'Non-authoritative answer:\nName:\tnode.example.com\nAddress: 2001:db8::7\n\n' ;;
    odd.example.com)
        printf 'Non-authoritative answer:\nName:\todd.example.com\nAddress: 203.0.113.7;flush\n\n' ;;
    *)
        printf "** server can't find %s: NXDOMAIN\n\n" "$1"
        return 1 ;;
    esac
}
# shellcheck disable=SC2317
lc_rules_down() { DOWN_CALLED=$((DOWN_CALLED + 1)); }
# `ip` is captured rather than merely silenced: the routing rule it adds and the mark the nft rules
# set are the SAME number in two places, and a live router was once found carrying a rule for one
# table while the code deleted another. Keeping the words lets that agreement be asserted.
IP_CMDS=""
# shellcheck disable=SC2317
ip() { IP_CMDS="$IP_CMDS
$*"; }

# Renders with one set of inputs and leaves the result in RULES / rc / NFT_CALLED / DOWN_CALLED.
#
# The arguments are written here in the order a reader would expect and handed over in the order the
# function takes them, which is `port clients node udp` — not the same one. Passing them as globals
# instead, which is what this did first, silently gave lc_rules_up four unset parameters.
#
# ⚠️ DOWN_CALLED IS NEVER ZERO. lc_rules_up opens by calling lc_rules_down unconditionally — "down
# first, always", so that starting behaves the same whether or not a previous start left anything.
# So a refusal shows as TWO calls, and `-ge 1` would have been an assertion that passes on every
# path including the ones it was written to catch.
render() {
    _node=$1; _clients=$2; _port=$3; _udp=$4
    DOWN_CALLED=0; IP_CMDS=""
    : > "$NFT_OUT"; : > "$NFT_CNT"
    lc_rules_up "$_port" "$_clients" "$_node" "$_udp"
    rc=$?
    RULES=$(cat "$NFT_OUT")
    NFT_CALLED=$(wc -l < "$NFT_CNT" | tr -d " ")
}

has()    { printf '%s\n' "$RULES" | grep -qF "$1"; }
lineno() { printf '%s\n' "$RULES" | grep -nF "$1" | head -1 | cut -d: -f1; }

printf 'the intercept ruleset, rendered from %s\n\n' "$INIT"

# ---------------------------------------------------------------- the ordinary case
render 203.0.113.7 "192.168.1.10 192.168.1.0/24" 12345 ""

[ "$rc" -eq 0 ] && ok "a plain IPv4 node with two clients renders" \
    || bad "a plain IPv4 node with two clients was refused (rc=$rc)"
[ "$NFT_CALLED" -eq 1 ] && ok "and it is applied in ONE nft call, which is what makes it atomic" \
    || bad "the ruleset reached nft $NFT_CALLED times; a partial state can exist"

has "add table inet lite_client" && ok "the table is created" || bad "no table"
has "type filter hook prerouting priority mangle; policy accept;" \
    && ok "the chain hooks prerouting at mangle priority" || bad "the chain hook or priority changed"
has "meta l4proto tcp socket transparent 1 meta mark set meta mark | $FWMARK counter accept" \
    && ok "packets of an open transparent socket are marked and accepted" \
    || bad "the socket-transparent rule for tcp is gone; return traffic would leave by the ordinary route"

# ⚠️ THE ORDER, which no amount of reading the rules one at a time would catch. nft evaluates a chain
# in insertion order, so the node's `return` has to be inserted before any rule that could match the
# tunnel's own packets to it.
_node_at=$(lineno "ip daddr 203.0.113.7 counter return")
_first_client=$(lineno "ip saddr 192.168.1.10")
if [ -n "$_node_at" ] && [ -n "$_first_client" ] && [ "$_node_at" -lt "$_first_client" ]; then
    ok "the node's exemption is inserted BEFORE the client rules, so the tunnel does not eat itself"
else
    bad "the node exemption is at line ${_node_at:-none} and the first client rule at ${_first_client:-none}"
fi

has "ip saddr 192.168.1.10 tcp dport { 80, 443 } tproxy ip to :12345 counter accept" \
    && ok "a listed client has 80 and 443 diverted to the tunnel's port" \
    || bad "the tcp intercept rule does not render as expected"
has "ip saddr 192.168.1.0/24 tcp dport { 80, 443 }" \
    && ok "a prefix is intercepted the same way as an address" || bad "the prefix client did not render"

# ⚠️ 53 MUST NOT APPEAR. Diverting DNS takes name resolution down with the tunnel, and the router's
# own resolver is what answers it. Checked against the whole ruleset rather than one line, because a
# port added anywhere is the failure.
printf '%s\n' "$RULES" | grep -q "dport.*53" \
    && bad "port 53 appears in the ruleset; DNS must not be diverted" \
    || ok "DNS is not diverted anywhere in the ruleset"

printf '%s\n' "$RULES" | grep -q "udp" \
    && bad "UDP rules rendered although no UDP port was configured" \
    || ok "with no UDP port configured, no UDP rule is written"

# ⚠️ ONE NUMBER IN TWO PLACES. The nft rules set a mark and the routing rule looks it up; a router was
# once found carrying `from all fwmark 0x1000000 lookup lctproxy` — table 101 — while the teardown
# deleted table 104, so the rule could never be removed and the guard that checked for it could never
# pass again. Harmless there only by luck. Both halves are rendered here, so they can be compared.
printf '%s\n' "$IP_CMDS" | grep -qF "rule add fwmark $FWMARK/$FWMARK lookup $RT_TABLE priority 102" \
    && ok "the routing rule looks up the same mark and table the nft rules set" \
    || bad "the ip rule does not match the mark or table used in the ruleset"
printf '%s\n' "$IP_CMDS" | grep -qF "route add local default dev lo table $RT_TABLE" \
    && ok "and that table has the local default route the marked packets need" \
    || bad "the local default route for the tproxy table is missing"

# ---------------------------------------------------------------- with UDP
render 203.0.113.7 "192.168.1.10" 12345 12346
[ "$rc" -eq 0 ] && ok "a configuration with a UDP port renders" || bad "the UDP configuration was refused"
has "meta l4proto udp socket transparent 1" \
    && bad "generic UDP diversion captures unselected packets in send-only reply sockets" \
    || ok "UDP follows selection instead of being diverted into send-only reply sockets"
has "ip saddr 192.168.1.10 udp dport 443 tproxy ip to :12346 counter accept" \
    && ok "UDP interception is QUIC's 443 and that port only" || bad "the udp intercept rule changed"

# ---------------------------------------------------------------- an IPv6 node
render 2001:db8::1 "192.168.1.10" 12345 ""
[ "$rc" -eq 0 ] && ok "an IPv6 node renders" || bad "an IPv6 node was refused"
has "ip6 daddr 2001:db8::1 counter return" \
    && ok "an IPv6 node is exempted with ip6 daddr" || bad "the IPv6 node exemption is wrong"
printf '%s\n' "$RULES" | grep -q "ip daddr 2001" \
    && bad "an IPv6 node rendered as ip daddr, which nft refuses and which cancels the whole ruleset" \
    || ok "and not as ip daddr, which would cancel the ruleset entirely"

# ---------------------------------------------------------------- a node given by name
# Taken since 2026-09-29, when the tunnel began looking a name up for every dial as the reference
# does; it used to be refused. Exempted by every address the name has at start, each by its family.
render node.example.com "192.168.1.10" 12345 ""
[ "$rc" -eq 0 ] && ok "a node given by name renders" || bad "a node given by name was refused"
has "ip daddr 203.0.113.7 counter return" && has "ip daddr 203.0.113.8 counter return" \
    && has "ip6 daddr 2001:db8::7 counter return" \
    && ok "and is exempted by each of its addresses, each by its family" \
    || bad "a named node's addresses are not all exempted"
printf '%s\n' "$RULES" | grep -q "daddr 127.0.0.1" \
    && bad "the resolver's own address, from nslookup's header, was taken for the node's" \
    || ok "and not by the address of the resolver that answered"
render nothing.example.com "192.168.1.10" 12345 ""
[ "$rc" -eq 0 ] && [ "$NFT_CALLED" -eq 1 ] && ! printf '%s\n' "$RULES" | grep -q "daddr .* counter return" \
    && ok "a name with no address yet starts, exempting nothing, as the reference starts" \
    || bad "a name with no address: rc=$rc nft=$NFT_CALLED"

# ---------------------------------------------------------------- fail closed
# Each of these must refuse BEFORE anything reaches the kernel. "Refused" is not enough on its own:
# the bug this replaced applied rules one at a time and failed partway, which is the state that
# leaves a LAN host with its traffic diverted into nothing.
render "odd.example.com" "192.168.1.10" 12345 ""
[ "$rc" -ne 0 ] && [ "$NFT_CALLED" -eq 0 ] && [ "$DOWN_CALLED" -ge 2 ] \
    && ok "a name answered with something that is not an address is refused before any rule" \
    || bad "a name answered with a non-address: rc=$rc nft=$NFT_CALLED down=$DOWN_CALLED"

render 203.0.113.7 "2001:db8::5" 12345 ""
[ "$rc" -ne 0 ] && [ "$NFT_CALLED" -eq 0 ] && [ "$DOWN_CALLED" -ge 2 ] \
    && ok "an IPv6 client is refused rather than silently left unintercepted" \
    || bad "an IPv6 client: rc=$rc nft=$NFT_CALLED down=$DOWN_CALLED"

render 203.0.113.7 "192.168.1.10 192.168.10.0/33" 12345 ""
[ "$rc" -ne 0 ] && [ "$NFT_CALLED" -eq 0 ] \
    && ok "a malformed prefix takes the whole ruleset with it, not just its own line" \
    || bad "a malformed prefix: rc=$rc nft=$NFT_CALLED"

render 203.0.113.7 "" 12345 ""
[ "$rc" -eq 0 ] && ok "an empty client list is not an error — it simply intercepts nobody" \
    || bad "an empty client list was refused (rc=$rc)"
printf '%s\n' "$RULES" | grep -q "saddr" \
    && bad "an empty client list still rendered a saddr rule" \
    || ok "and writes no saddr rule at all"


# ==================================================================== the teardown
#
# Raised rules that cannot be taken down are the same failure as rules that should never have gone
# up: the LAN keeps 80 and 443 diverted into a socket nobody is listening on. Everything asserted
# below comes from an incident rather than from reading:
#
#   - the loop, because the first version deleted ONE rule per stop while each start added one, so a
#     service restarted twelve times left eleven behind and the router began delivering marked
#     packets to itself;
#   - deleting by MARK ALONE, because naming the table made the loop unable to remove a rule this
#     same service had created under an older RT_TABLE — found on a live box carrying two rules for
#     one mark, where the documented health check could never pass again;
#   - the bound, so that a kernel which somehow always succeeds cannot spin here forever.
#
# The real function replaces the stub only now, after every assertion about lc_rules_up has been
# made — it is lc_rules_up's own first call, and a real one there would have deleted the routing
# rules those tests were reading.
eval "$(extract lc_rules_down)"

IP_V4_OK=0
IP_V4_SEEN=0
IP_V6_SEEN=0
# shellcheck disable=SC2317
ip() {
    IP_CMDS="$IP_CMDS
$*"
    case "$*" in
    "-6 rule del"*) IP_V6_SEEN=$((IP_V6_SEEN + 1)); return 1 ;;
    "-4 rule del fwmark $FWMARK/$FWMARK lookup $RT_TABLE priority 102")
        IP_V4_SEEN=$((IP_V4_SEEN + 1))
        [ "$IP_V4_SEEN" -le "$IP_V4_OK" ] && return 0
        return 1 ;;
    "-4 rule del"*) return 1 ;;
    esac
    return 0
}

teardown() {
    IP_V4_OK=$1; IP_V4_SEEN=0; IP_V6_SEEN=0; IP_CMDS=""; NFT_ARGS=""
    lc_rules_down
    rc=$?
}

printf '\n'

# Nothing to remove at all — a stop after a start that never got as far as raising anything.
teardown 0
[ "$rc" -eq 0 ] && ok "a teardown with nothing to remove still succeeds" \
    || bad "the teardown failed on an empty state (rc=$rc)"
[ "$IP_V4_SEEN" -eq 1 ] && ok "and it asks exactly once before believing there is nothing left" \
    || bad "it asked $IP_V4_SEEN times where one refusal was the answer"

# Cleanup has a narrow current selector plus explicit historical migrations.
printf '%s\n' "$IP_CMDS" | grep -qF -- "-4 rule del fwmark $FWMARK/$FWMARK lookup $RT_TABLE priority 102" \
    && ok "current deletion preserves foreign masked selectors" || bad "current selector is too broad"
for old_table in 101 104; do
    printf '%s\n' "$IP_CMDS" | grep -qF -- "-4 rule del fwmark 0x40404 lookup $old_table" \
        && ok "historical table $old_table is explicitly retired" || bad "legacy selector remains"
done

# Three left over from three starts that were never stopped.
teardown 3
[ "$IP_V4_SEEN" -eq 4 ] \
    && ok "three leftover rules take four attempts — it deletes until the kernel says there are none" \
    || bad "with three rules present it made $IP_V4_SEEN attempts, not four"

# A kernel that never runs out. The loop must stop on its own.
teardown 1000
[ "$IP_V4_SEEN" -eq 32 ] && ok "and it stops at thirty-two rather than spinning forever" \
    || bad "the bound did not hold: $IP_V4_SEEN attempts"

teardown 0
[ "$IP_V6_SEEN" -ge 1 ] && ok "IPv6 routing rules are removed too, not only IPv4" \
    || bad "nothing deleted the IPv6 rule; it would survive every stop"
printf '%s\n' "$IP_CMDS" | grep -qF "route flush table $RT_TABLE" \
    && ok "the tproxy routing table is flushed" || bad "the routing table is left populated"
printf '%s\n' "$IP_CMDS" | grep -qF -- "-6 route flush table $RT_TABLE" \
    && ok "and its IPv6 half as well" || bad "the IPv6 routing table is left populated"
printf '%s\n' "$NFT_ARGS" | grep -qF "delete table inet lite_client" \
    && ok "the nft table is removed, so nothing keeps diverting" || bad "the nft table is left behind"

printf '\n'
if [ "$fails" -eq 0 ]; then
    printf 'the ruleset diverts what it says, refuses closed, and comes down again\n'
else
    printf 'the intercept ruleset has CHANGED shape\n'
    exit 1
fi
