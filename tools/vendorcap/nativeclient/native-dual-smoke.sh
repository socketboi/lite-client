#!/bin/sh
# Bounded device data-path check. No packages, services, UCI or routing are changed.
set -eu
test "$#" -eq 1
driver=$(readlink -f "$0")
work=$(readlink -f "$1")
case "$work" in /tmp/lc-dual-*) ;; *) exit 2 ;; esac
cd "$work"
umask 077
test ! -e result.json
sha256sum -c device.sha256 > input-check.log
expected_driver=$(awk '$2=="native-dual-smoke.sh" {print $1}' device.sha256)
test -n "$expected_driver"
test "$(sha256sum "$driver" | cut -d' ' -f1)" = "$expected_driver"
. ./settings.sh
case "$RUN_LABEL" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
test "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$EXPECTED_BOOT"
chmod 700 client probe
test "$(./client --version)" = "$EXPECTED_VERSION"
test "$(./client --planes)" = "$(printf 'reality\nhysteria')"
exec 8>/var/run/lc-native-lab.lock
flock -n 8 || exit 75
# Refuse another test's listeners before starting an owned process group.
for file in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    awk 'NR>1 && $2 ~ /:(4E03|4C91)$/ {found=1} END {exit found}' "$file"
done
snapshot() {
    cat /proc/sys/kernel/random/boot_id > "boot-$1"
    find /etc/config -type f -exec sha256sum '{}' \; | sort > "configuration-$1"
    ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > "interfaces-$1"
    ip -4 -N rule show > "rules4-$1"
    ip -6 -N rule show > "rules6-$1"
}
snapshot before
pid= loads= completed=0
started=$(cut -d. -f1 /proc/uptime)
stop_client() {
    ./probe gone "$pid" && return 0
    kill -TERM "-$pid" 2>/dev/null || :
    # A supervisor exit precedes worker teardown and init's orphan reaping.
    # Require the entire owned process group to disappear within the bound.
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        ./probe gone "$pid" && return 0
        sleep 1
    done
    kill -KILL "-$pid" 2>/dev/null || :
    return 1
}
finish() {
    status=$?
    trap - EXIT HUP INT TERM
    for load in $loads; do kill "$load" 2>/dev/null || :; done
    for load in $loads; do wait "$load" 2>/dev/null || :; done
    if test -n "$pid"; then
        stop_client || status=1
        wait "$pid" 2>/dev/null || :
        ./probe gone "$pid" || status=1
    fi
    snapshot after || status=1
    for name in boot configuration interfaces rules4 rules6; do
        cmp "$name-before" "$name-after" || status=1
    done
    printf '{"exit":%s,"cases_completed":%s,"elapsed_seconds":%s,"scope":"temporary native TCP/TLS/UDP; no package or service lifecycle"}\n' \
        "$status" "$completed" "$(($(cut -d. -f1 /proc/uptime)-started))" > result.json
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
export SSL_CERT_FILE="$work/cert.pem"
unset GOGC GOMEMLIMIT GOMAXPROCS GODEBUG
for workers in 1 4; do
    for plane in reality hysteria-none hysteria-salamander; do
        role=$plane-$workers
        if test "$plane" = reality; then
            set -- fingerprint.fpt "$PEER" "$REALITY_PORT" smoke.test "$PUBLIC_KEY" "$SHORT_ID" \
                "@$work/uuid" 19971 -f xtls-rprx-vision
        else
            port=$HYSTERIA_PORT; obfs=-
            if test "$plane" = hysteria-salamander; then port=$SALAMANDER_PORT; obfs="@$work/obfs"; fi
            set -- -H "$PEER" "$port" smoke.test "@$work/auth" "$obfs" 19971 -p "$CERT_PIN"
        fi
        setsid ./client "$@" -w "$workers" -t 127.0.0.1:29762 -u 19601@127.0.0.1:29763 \
            > "$role.client.log" 2>&1 &
        pid=$!
        ready=0
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid"
            if awk '$2 ~ /:4E03$/ && $4=="0A" {found=1} END {exit !found}' /proc/net/tcp /proc/net/tcp6; then ready=1; break; fi
            sleep 1
        done
        test "$ready" = 1
        test "$(sha256sum "/proc/$pid/exe" | cut -d' ' -f1)" = "$(sha256sum client | cut -d' ' -f1)"
        expected=1; test "$workers" = 1 || expected=5
        listeners=$expected
        # The REALITY supervisor retains its shared listener; the Hysteria
        # supervisor closes it after forking its independent QUIC workers.
        test "$plane" = reality || listeners=$workers
        ready=0
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid"
            if ./probe sample "$pid" "$expected" > "$role.resources-before.json" &&
               jq -e --argjson n "$expected" --argjson listeners "$listeners" \
                   '(.tasks|length)==$n and .tcp_listener_fds==$listeners' "$role.resources-before.json" >/dev/null; then
                ready=1; break
            fi
            sleep 1
        done
        test "$ready" = 1
        loads=
        for stream in 1 2 3 4; do
            scheme=http; case "$stream" in 2|4) scheme=https ;; esac
            (
                curl -q -fsS --http1.1 --noproxy '*' --connect-timeout 5 --max-time 30 \
                    --resolve smoke.test:19971:127.0.0.1 --cacert cert.pem \
                    "$scheme://smoke.test:19971/$RUN_LABEL/$role/$stream" -o "$role.$stream.body"
                test "$(wc -c < "$role.$stream.body")" = 1048576
                test "$(sha256sum "$role.$stream.body" | cut -d' ' -f1)" = "$BODY_SHA"
                rm "$role.$stream.body"
            ) > "$role.$stream.log" 2>&1 &
            loads="$loads $!"
        done
        failed=0
        for load in $loads; do wait "$load" || failed=1; done
        loads=
        test "$failed" = 0
        ./probe udp 19601 > "$role.udp.json"
        jq -e '.echoes==64 and .bytes==8192' "$role.udp.json" >/dev/null
        kill -0 "$pid"
        ./probe sample "$pid" "$expected" > "$role.resources-after.json"
        stop_client
        code=0; wait "$pid" || code=$?
        test "$code" = 143
        ./probe gone "$pid"
        pid=
        completed=$((completed+1))
        printf 'PASS %s: TCP/TLS payloads, 64 UDP echoes, process cleanup\n' "$role"
    done
done
test "$completed" = 6
