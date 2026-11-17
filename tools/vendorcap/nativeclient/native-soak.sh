#!/bin/sh
# Temporary native mixed-load/reclamation test. No installed services or network policy changes.
set -eu
test "$#" -eq 1
driver=$(readlink -f "$0")
work=$(readlink -f "$1")
case "$work" in /tmp/lc-native-soak-*) ;; *) exit 2;; esac
cd "$work"
test ! -e device-state.json
sha256sum -c device.sha256
expected_driver=$(awk '$2=="native-soak.sh" {print $1}' device.sha256)
test -n "$expected_driver"
test "$(sha256sum "$driver" | awk '{print $1}')" = "$expected_driver"
. ./settings.sh
test "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$EXPECTED_BOOT"
cat /tmp/sysinfo/board_name > board-name
chmod 700 client probe
cp /proc/sys/kernel/random/boot_id boot-before
find /etc/config -type f -exec sha256sum '{}' \; | sort > configuration-before
ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-before
started=$(cut -d. -f1 /proc/uptime)
pid= monitor= loads= cleanup_exit=0 completed=0
now() { cut -d. -f1 /proc/uptime; }
alive() { test -n "$pid" && kill -0 "$pid" 2>/dev/null; }
healthy() { alive && test ! -e monitor.failed; }
stop_client() {
    if alive; then
        kill -TERM "-$pid" 2>/dev/null || true
        n=0
        while alive && test "$n" -lt 15; do sleep 1; n=$((n+1)); done
        if alive; then kill -KILL "-$pid" 2>/dev/null || true; cleanup_exit=1; fi
    fi
}
finish() {
    status=$?
    trap - EXIT INT TERM HUP
    for load in $loads; do kill -TERM "$load" 2>/dev/null || true; done
    for load in $loads; do wait "$load" 2>/dev/null || true; done
    if test -n "$monitor"; then kill "$monitor" 2>/dev/null || true; wait "$monitor" 2>/dev/null || true; fi
    stop_client
    if test -n "$pid"; then wait "$pid" 2>/dev/null || true; fi
    cp /proc/sys/kernel/random/boot_id boot-after
    find /etc/config -type f -exec sha256sum '{}' \; | sort > configuration-after
    ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-after
    printf '{"exit_code":%s,"cleanup_exit":%s,"roles_completed":%s,"elapsed_seconds":%s}\n' \
        "$status" "$cleanup_exit" "$completed" "$(($(now)-started))" > device-state.json
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
stage() { printf '%s %s %s\n' "$role" "$epoch" "$1" > monitor-stage.next; mv monitor-stage.next monitor-stage; }
sample() {
    test "$(($(now)-started))" -lt "$MAXIMUM_SECONDS" || return 1
    values=$(./probe sample "$pid" "$expected") || return 1
    metadata=$(cat monitor-stage) || return 1
    available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo) || return 1
    set -- $metadata
    printf '{"role":"%s","epoch":%s,"stage":"%s","elapsed":%s,"memavailable_kib":%s,"sample":%s}\n' \
        "$1" "$2" "$3" "$(($(now)-started))" "$available" "$values" >> resources.jsonl
}
for workers in 1 4; do
    role=lc$workers
    epoch=0
    expected=1
    test "$workers" -eq 1 || expected=5
    setsid ./client fingerprint.fpt "$SERVER_ADDRESS" 29600 soak.test "$PUBLIC_KEY" "$SHORT_ID" \
        "@$work/uuid" 19971 -t 127.0.0.1:29622 -u 19601@127.0.0.1:29623 -f xtls-rprx-vision -w "$workers" \
        > "$role.client.log" 2>&1 &
    pid=$!
    n=0
    until ./probe check "$pid" "$expected" > "$role.ready.json"; do
        alive
        n=$((n+1)); test "$n" -lt 10
        sleep 1
    done
    binary_sha=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
    test "$binary_sha" = "$CLIENT_SHA256"
    stage ready
    sample
    (while alive; do sample || { touch monitor.failed; exit 1; }; sleep 1; done) & monitor=$!
    for epoch in 1 2; do
        active_started=$(now)
        stage active
        burst=0
        while test "$burst" -lt "$BURSTS_PER_EPOCH"; do
            due=$((active_started+burst*10))
            while test "$(now)" -lt "$due"; do healthy; sleep 1; done
            healthy
            ./probe udp 19601 > "$role.$epoch.$burst.udp.json" 2> "$role.$epoch.$burst.udp.log" &
            loads=$!
            for stream in 1 2 3 4; do
                scheme=http
                case "$stream" in 2|4) scheme=https;; esac
                curl -q -fsS --noproxy '*' --http1.1 --connect-timeout 5 --max-time 15 \
                    --resolve soak.test:19971:127.0.0.1 --cacert "$work/cert.pem" \
                    --header 'Connection: close' "$scheme://soak.test:19971/payload?case=$role.$epoch.$burst.$stream" \
                    -o "$role.$epoch.$burst.$stream.body" 2> "$role.$epoch.$burst.$stream.curl.log" &
                loads="$loads $!"
            done
            load_failed=0
            for load in $loads; do wait "$load" || load_failed=1; done
            loads=
            test "$load_failed" -eq 0
            for stream in 1 2 3 4; do
                body="$role.$epoch.$burst.$stream.body"
                actual=$(sha256sum "$body" | awk '{print $1}')
                test "$actual" = "$PAYLOAD_SHA256"
                test "$(wc -c < "$body")" -eq 1048576
                printf '%s  %s\n' "$actual" "$body" >> payloads.sha256
                rm -f "$body"
            done
            printf '{"role":"%s","epoch":%s,"burst":%s,"elapsed":%s,"tcp_cases":4,"tcp_bytes":4194304,"udp_echoes":64}\n' \
                "$role" "$epoch" "$burst" "$(($(now)-started))" >> bursts.jsonl
            printf 'BURST_COMPLETE %s %s %s\n' "$role" "$epoch" "$burst"
            burst=$((burst+1))
        done
        while test "$(now)" -lt "$((active_started+ACTIVE_SECONDS))"; do healthy; sleep 1; done
        stage idle
        idle_started=$(now)
        printf '%s %s %s\n' "$role" "$epoch" "$idle_started" >> idle-started.tsv
        while test "$(now)" -lt "$((idle_started+190))"; do healthy; sleep 1; done
        ./probe check "$pid" "$expected" > "$role.$epoch.quiescent.json"
        printf '%s %s %s\n' "$role" "$epoch" "$(now)" >> idle-finished.tsv
        sample
        printf 'QUIESCENT_COMPLETE %s %s\n' "$role" "$epoch"
    done
    healthy
    sample
    kill "$monitor"
    monitor_exit=0
    wait "$monitor" || monitor_exit=$?
    monitor=
    test "$monitor_exit" -eq 143
    stop_client
    client_exit=0
    wait "$pid" || client_exit=$?
    test "$client_exit" -eq 143
    ./probe gone "$pid"
    pid=
    test "$cleanup_exit" -eq 0
    printf '{"role":"%s","binary_sha256":"%s","client_exit":%s,"monitor_exit":%s}\n' \
        "$role" "$binary_sha" "$client_exit" "$monitor_exit" > "$role.receipt.json"
    completed=$((completed+1))
done
sha256sum -c device.sha256
