#!/bin/sh
# Opt-in lab check: a network-namespace LAN client, real NAT and native TPROXY.
# All peers and credentials are supplied by a private, frozen staging directory.
set -eu
test "$#" -eq 1
driver=$(readlink -f "$0")
b=$(readlink -f "$1")
case "$b" in /tmp/lc-lan-*) ;; *) exit 2 ;; esac
cd "$b"
umask 077
test ! -e result.json
sha256sum -c device.sha256 > input-check.log
expected=$(awk '$2=="native-lan.sh" {print $1}' device.sha256)
test -n "$expected" && test "$(sha256sum "$driver" | cut -d' ' -f1)" = "$expected"
. ./settings.sh
test "$LAB_ROUTER_ACK" = 1
test "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD"
test "$(sha256sum /usr/sbin/lc-tunnel | cut -d' ' -f1)" = "$CLIENT_SHA"
test "$(sha256sum /etc/init.d/lite-client | cut -d' ' -f1)" = "$SERVICE_SHA"
exec 8>/var/run/lc-native-lab.lock
flock -n 8 || exit 75
if pidof lc-tunnel >/dev/null 2>&1; then exit 2; fi
test "$(uci -q get lite-client.main.enabled)" = 0
ip -4 addr show dev br-lan | grep -F "inet $LAN_GATEWAY/24 " >/dev/null
test ! -e /var/run/netns/lc-lan-path
if ip link show lc-lan-host >/dev/null 2>&1; then exit 2; fi
if nft list table inet lc_lan_path >/dev/null 2>&1; then exit 2; fi
test -z "$(ip -4 route show table 40406 2>/dev/null)"
if ip -4 rule show | grep -q '^10406:'; then exit 2; fi
mkdir -p state run
export INSTALL_DIR="$b/state"
sed "s|/var/run/|$b/run/|g" router-lib.sh > runtime.sh
. ./runtime.sh
for address in "$PEER" "$CLIENT_IPV4" "$LAN_GATEWAY"; do
    jq -ne --arg address "$address" "$DOMAIN_POLICY_JSON_JQ"'$address|ipv4' >/dev/null
done
cp -p /etc/config/lite-client original.uci
snapshot() {
    find /etc/config -type f > config-list || return 1
    while IFS= read -r file; do sha256sum "$file" || return 1; done < config-list > config-raw
    sort config-raw > "config-$1" || return 1
    sha256sum /etc/dropbear/dropbear_*_host_key > "hostkeys-$1" || return 1
    sha256sum /etc/init.d/lite-client > "service-$1" || return 1
    cat /proc/sys/kernel/random/boot_id > "boot-$1" || return 1
    ip -o link show > links-raw || return 1
    sed 's/^[0-9]*: //;s/:.*//' links-raw | sort > "interfaces-$1" || return 1
    ip -4 rule show > "rules-$1" || return 1
    ip -4 route show table main > "routes-$1" || return 1
    ip -6 rule show > "rules6-$1" || return 1
    ip -6 route show table main > "routes6-$1" || return 1
    dmesg > oom-raw || return 1
    awk '/oom-killer|oom-kill:|Out of memory:|Killed process/' oom-raw > "oom-$1" || return 1
    : > "dns-$1" || return 1
    for pid in $(pidof dnsmasq); do awk -v pid="$pid" '{print pid " " $22}' "/proc/$pid/stat" >> "dns-$1" || return 1; done
    test -s "dns-$1" || return 1
    sort "dns-$1" > "dns-$1.tmp" && mv "dns-$1.tmp" "dns-$1" || return 1
}
snapshot before
namespace=0; link=0; table=0; rule=0; route=0; finished=0
finish() {
    rc=$?
    trap - EXIT HUP INT TERM
    set +e
    clean=0
    lite_client_stop || clean=1
    lite_client_disable || clean=1
    if [ "$rule" = 1 ]; then ip -4 rule del priority 10406 fwmark 0x40406 lookup 40406 || clean=1; fi
    if [ "$route" = 1 ]; then ip -4 route del local 0.0.0.0/0 dev lo table 40406 || clean=1; fi
    if [ "$table" = 1 ]; then nft delete table inet lc_lan_path || clean=1; fi
    if [ "$namespace" = 1 ]; then
        for pid in $(ip netns pids lc-lan-path); do kill "$pid" || clean=1; done
    fi
    if [ "$link" = 1 ]; then ip link delete lc-lan-host || clean=1; fi
    if [ "$namespace" = 1 ]; then ip netns delete lc-lan-path || clean=1; fi
    snapshot after || clean=1
    for name in hostkeys service boot interfaces rules routes rules6 routes6 oom dns; do cmp "$name-before" "$name-after" || clean=1; done
    printf '{"exit":%s,"cleanup":%s,"finished":%s,"profile_retained":true}\n' "$rc" "$clean" "$finished" > result.json
    printf 'LAN_PATH_RESULT exit=%s cleanup=%s finished=%s\n' "$rc" "$clean" "$finished"
    [ "$rc" = 0 ] && [ "$clean" = 0 ] && [ "$finished" = 1 ]
}
trap finish EXIT
trap 'exit 143' HUP TERM
trap 'exit 130' INT
ip netns add lc-lan-path; namespace=1
ip link add lc-lan-host type veth peer name lc-lan-guest; link=1
# Keep the bridge's existing automatic MAC below this temporary port's address.
ip link set lc-lan-host address fe:ff:ff:ff:ff:fe
ip link set lc-lan-host master br-lan
ip link set lc-lan-host up
ip link set lc-lan-guest netns lc-lan-path
ip -n lc-lan-path link set lo up
ip -n lc-lan-path addr add "$CLIENT_IPV4/24" dev lc-lan-guest
ip -n lc-lan-path link set lc-lan-guest up
ip -n lc-lan-path route add default via "$LAN_GATEWAY"
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ "$(cat /sys/class/net/lc-lan-host/brport/state)" = 3 ] && break
    sleep 1
done
test "$(cat /sys/class/net/lc-lan-host/brport/state)" = 3
# First check normal forwarding/NAT with no native process or interception.
nft -f - <<NFT
table inet lc_lan_path {
    set selected4 { type ipv4_addr; }
    chain inbound { type filter hook prerouting priority -151; policy accept;
        iifname "br-lan" ip saddr $CLIENT_IPV4 ip daddr @selected4 tcp dport 29662 counter tproxy ip to 127.0.0.1:19999 meta mark set 0x40406 accept
        iifname "br-lan" ip saddr $CLIENT_IPV4 ip daddr @selected4 udp dport 29663 counter tproxy ip to 127.0.0.1:19998 meta mark set 0x40406 accept
    }
}
NFT
table=1
ip -4 route add local 0.0.0.0/0 dev lo table 40406; route=1
ip -4 rule add priority 10406 fwmark 0x40406 lookup 40406; rule=1
traffic() {
    label=$1
    for stream in 1 2 3 4; do
        scheme=http; case "$stream" in 2|4) scheme=https ;; esac
        ip netns exec lc-lan-path curl -q -fsS --http1.1 --noproxy '*' --connect-timeout 5 --max-time 30 \
            --resolve "hy-soak.test:29662:$PEER" --cacert "$b/cert.pem" -H 'Connection: close' \
            "$scheme://hy-soak.test:29662/$label/0/$stream" -o "$b/body"
        test "$(wc -c < body)" = 1048576
        test "$(sha256sum body | cut -d' ' -f1)" = "$BODY_SHA"
        printf '%s\t%s\t%s\n' "$label" "$stream" "$BODY_SHA" >> payloads.tsv
        rm body
    done
    ip netns exec lc-lan-path "$b/probe" udp 29663 "$PEER" > "$label.udp.json"
    jq -e '.echoes==64 and .bytes==8192' "$label.udp.json" >/dev/null
    printf '{"label":"%s","tcp":4,"udp":64}\n' "$label" >> traffic.jsonl
    printf 'LAN_CASE %s\n' "$label"
}
traffic nat
uci set lite-client.main.uuid_file=/etc/lite-client/uuid
uci set lite-client.main.listen_port=19999
uci set lite-client.main.udp_port=19998
uci -q delete lite-client.main.workers || :
uci commit lite-client
printf lite > "$INSTALL_DIR/engine"
read_api_url() { printf https://fixture.invalid/api; }
read_token() { printf fixture; }
curl() { case "$*" in *fixture.invalid/api/router/*-config*) cat "$b/current.response" ;; *) command curl "$@" ;; esac; }
apply_plane_routing() { nft list table inet lc_lan_path >/dev/null; }
fw4() (
    # Owner firewall hooks must not inherit the test's private runtime paths.
    unset INSTALL_DIR SHARE_DIR ROUTER_RUNTIME_DIR VPN_PLANE_LOCK
    command fw4 "$@"
)
pid_now() { ubus call service list '{"name":"lite-client"}' | jq -er '."lite-client".instances.instance1.pid|select(type=="number" and .>0)'; }
for plane in reality hysteria; do
    . "$b/plane-$plane.sh"
    cp "$plane.response" current.response
    plane_prepare_config
    # Run the real fw4 reload in lite_client_start; this is a dedicated test router.
    plane_start
    pid=$(pid_now)
    nft add element inet lc_lan_path selected4 "{ $PEER }"
    traffic "$plane-selected"
    test "$(pid_now)" = "$pid"
    nft delete element inet lc_lan_path selected4 "{ $PEER }"
    traffic "$plane-direct"
    test "$(pid_now)" = "$pid"
    nft add element inet lc_lan_path selected4 "{ $PEER }"
    fw4 reload
    traffic "$plane-reloaded"
    test "$(pid_now)" = "$pid"
    printf '{"plane":"%s","pid":%s,"stable":true,"firewall_reload":true}\n' "$plane" "$pid" >> phases.jsonl
    nft -j list table inet lc_lan_path > "$plane.kernel.json"
    nft delete element inet lc_lan_path selected4 "{ $PEER }"
    lite_client_stop
    lite_client_disable
done
finished=1
