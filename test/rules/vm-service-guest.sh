#!/bin/sh
# Actual procd/ubus/rc.common, actual APK hooks, and no external network adapter.
exec </dev/console >/dev/console 2>&1
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
finish() { echo "LC_SERVICE_RESULT=$1" >&2; sync; poweroff -f; while :; do sleep 1; done; }
fail() {
    echo "LC_SERVICE_FAILURE $*" >&2
    logread | tail -30 >&2
    for file in /tmp/backend.log /tmp/cover.log /tmp/xray.log /tmp/reference.log; do tail -8 "$file" >&2; done
    finish 1
}
need() { "$@" || fail "$*"; }
wait_log() {
    count=0
    while [ "$count" -lt 20 ]; do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 1; count=$((count+1)); done
    fail "not ready: $1"
}
pid() { ubus -t 1 call service list '{"name":"lite-client"}' | jsonfilter -e '@["lite-client"].instances.instance1.pid'; }
listen() { awk -v hex="$1" '$2 ~ (":"hex"$") && $4 == "0A" { found=1 } END {exit !found}' /proc/net/tcp /proc/net/tcp6; }
wait_listener() {
    count=0
    hex=$(printf '%04X' "$1")
    while [ "$count" -lt 20 ]; do listen "$hex" && return 0; sleep 1; count=$((count+1)); done
    fail "listener not ready: $1"
}
capture() {
    process=$(pid)
    [ -n "$process" ] || process=0
    live=''
    [ -r "/proc/$process/exe" ] && live=$(sha256sum "/proc/$process/exe" | awk '{print $1}')
    disk=$(sha256sum /usr/sbin/lc-tunnel | awk '{print $1}')
    {
        printf '{"pid":%s,"live_sha256":"%s","disk_sha256":"%s","procd":' "$process" "$live" "$disk"
        need ubus -t 1 call service list '{"name":"lite-client"}'
        printf ',"rules":'; need ip -j rule show
        printf ',"nft":'; need nft -j list ruleset
        printf ',"native":['
        separator=''
        for executable in /proc/[0-9]*/exe; do
            target=$(readlink "$executable" 2>/dev/null) || continue
            case "$target" in /usr/sbin/lc-tunnel|'/usr/sbin/lc-tunnel (deleted)') ;; *) continue ;; esac
            native_pid=${executable#/proc/}; native_pid=${native_pid%/exe}
            native_hash=$(sha256sum "$executable" 2>/dev/null | awk '{print $1}')
            [ -n "$native_hash" ] || continue
            printf '%s{"pid":%s,"sha256":"%s"}' "$separator" "$native_pid" "$native_hash"
            separator=,
        done
        printf ']'
        printf '}\n'
    } > /tmp/state.json
    printf 'LC_SERVICE_STATE %s ' "$1"
    need hexdump -v -e '1/1 "%02x"' /tmp/state.json
    printf '\n'
}
emit() {
    printf 'LC_SERVICE_FILE %s ' "$1"
    need hexdump -v -e '1/1 "%02x"' "$2"
    printf '\n'
}
probe() { need ip netns exec lan /opt/bundle/peer "$1" /opt/bundle "$2" >> /tmp/client.jsonl; }
credentials() { sha256sum /etc/config/lite-client /etc/lite-client/uuid /etc/lite-client/auth /etc/lite-client/obfs; }
start_node() {
    /opt/bundle/xray run -c /opt/bundle/server.json > /tmp/xray.log 2>&1 &
    node_pid=$!
    wait_listener 29600
}

echo "LC_SERVICE_PID1=$(cat /proc/1/comm)"
/sbin/logd -S 64 > /tmp/logd.log 2>&1 &
need ip link set lo up
need ip netns add lan
need ip netns add backend
need ip link add lan-root type veth peer name lan-peer
need ip link set lan-peer netns lan
need ip addr add 192.0.2.1/24 dev lan-root
need ip link set lan-root up
need ip netns exec lan ip link set lo up
need ip netns exec lan ip addr add 192.0.2.7/24 dev lan-peer
need ip netns exec lan ip link set lan-peer up
need ip netns exec lan ip route add default via 192.0.2.1
need ip link add backend-root type veth peer name backend-peer
need ip link set backend-peer netns backend
need ip addr add 198.51.100.1/24 dev backend-root
need ip link set backend-root up
need ip netns exec backend ip link set lo up
need ip netns exec backend ip addr add 198.51.100.9/24 dev backend-peer
need ip netns exec backend ip link set backend-peer up
# LAN cannot reach the backend by routing around the proxy. Root-originated
# reference/node connections can reach its directly connected veth namespace.
echo 0 > /proc/sys/net/ipv4/ip_forward
ip netns exec backend /opt/bundle/peer serve /opt/bundle > /tmp/backend.log 2>&1 &
backend_pid=$!
/opt/bundle/peer cover /opt/bundle > /tmp/cover.log 2>&1 &
cover_pid=$!
wait_log /tmp/backend.log LC_BACKEND_READY
wait_log /tmp/cover.log LC_COVER_READY
start_node
/opt/bundle/xray run -c /opt/bundle/reference.json > /tmp/reference.log 2>&1 &
reference_pid=$!
wait_listener 29900
need /opt/bundle/peer reference /opt/bundle reference-control >> /tmp/client.jsonl
probe blocked before-service

if [ -e /opt/restore.tgz ]; then
    need apk --no-network --no-cache --force-non-repository add --allow-untrusted /opt/bundle/lite-client-hysteria-0.1.0-r2.apk
    need sysupgrade -r /opt/restore.tgz
    need /etc/init.d/lite-client start
    capture restored
    probe probe restored
else
    need apk --no-network --no-cache --force-non-repository add --allow-untrusted /opt/bundle/old-fixture.apk
    need cp /opt/bundle/client.uci /etc/config/lite-client
    need cp /opt/bundle/uuid /etc/lite-client/uuid
    printf 'fixture-auth\n' > /etc/lite-client/auth
    printf 'fixture-obfs\n' > /etc/lite-client/obfs
    need chmod 600 /etc/config/lite-client /etc/lite-client/uuid /etc/lite-client/auth /etc/lite-client/obfs
    need /etc/init.d/lite-client start
    capture old-running
    probe probe old-running
    old_pid=$(pid)
    need kill -KILL "$old_pid"
    sleep 6
    wait_listener 19099
    capture respawn
    probe probe respawn
    need uci set lite-client.main.workers=4
    need uci commit lite-client
    need /etc/init.d/lite-client reload
    capture four-workers
    probe probe four-workers
    old_pid=$(pid)
    need kill -KILL "$old_pid"
    sleep 6
    wait_listener 19099
    capture four-respawn
    probe probe four-respawn
    credentials > /tmp/credentials-before
    need apk --no-network --no-cache --force-non-repository add --allow-untrusted /opt/bundle/lite-client-hysteria-0.1.0-r2.apk
    capture upgraded
    credentials > /tmp/credentials-after
    need cmp /tmp/credentials-before /tmp/credentials-after
    probe probe upgraded
    need sysupgrade -b /tmp/backup.tgz
    emit backup /tmp/backup.tgz
    emit credentials /tmp/credentials-after
    need uci set lite-client.main.enabled=0
    need uci commit lite-client
    need /etc/init.d/lite-client start
    capture disabled
    probe blocked disabled
    need uci set lite-client.main.enabled=1
    need uci commit lite-client
    need /etc/init.d/lite-client start
    capture reenabled
    probe probe reenabled
    need uci set lite-client.main.node=''
    need uci commit lite-client
    if /etc/init.d/lite-client start; then fail 'invalid configuration reported success'; fi
    capture invalid
    probe blocked invalid
    need uci set lite-client.main.node=127.0.0.1
    need uci commit lite-client
    need /etc/init.d/lite-client start
    capture config-recovered
    probe probe config-recovered
    # A TCP-only supervisor keeps the shared listener even with no consumers.
    need uci delete lite-client.main.udp_port
    need uci commit lite-client
    need /etc/init.d/lite-client reload
    capture tcp-only
    supervisor=$(pid)
    # Freeze the replacement loop so the no-worker state is deterministic.
    need kill -STOP "$supervisor"
    workers=$(awk -v parent="$supervisor" '$1 == "PPid:" && $2 == parent {
        split(FILENAME,path,"/"); print path[3]
    }' /proc/[0-9]*/status)
    [ -n "$workers" ] || fail 'no workers to interrupt'
    need kill -KILL $workers
    sleep 1
    if /etc/init.d/lite-client start; then fail 'supervisor without consumers reported ready'; fi
    capture worker-gap
    probe blocked worker-gap
    emit before-worker-resume /tmp/backend.jsonl
    need kill -CONT "$supervisor"
    sleep 6
    need /etc/init.d/lite-client start
    capture tcp-recovered
    need uci set lite-client.main.udp_port=19098
    need uci commit lite-client
    need /etc/init.d/lite-client reload
    capture udp-restored
    probe probe udp-restored
    need /etc/init.d/lite-client stop
    sleep 1
    /opt/bundle/peer occupy /opt/bundle > /tmp/occupy.log 2>&1 &
    occupy_pid=$!
    wait_log /tmp/occupy.log LC_OCCUPY_READY
    if /etc/init.d/lite-client start; then fail 'unowned listener reported readiness'; fi
    capture occupied
    probe blocked occupied
    need kill "$occupy_pid"
    sleep 6
    wait_listener 19099
    capture bind-recovered
    probe probe bind-recovered
fi
need /usr/sbin/lc-tunnel --version > /tmp/package-version
emit version /tmp/package-version
credentials > /tmp/final-credentials
emit final-credentials /tmp/final-credentials
need /etc/init.d/lite-client stop
sleep 1
capture stopped
probe blocked after-stop
emit clients /tmp/client.jsonl
emit backend /tmp/backend.jsonl
emit access /tmp/xray-access.log
need kill "$reference_pid" "$node_pid" "$cover_pid" "$backend_pid"
finish 0
