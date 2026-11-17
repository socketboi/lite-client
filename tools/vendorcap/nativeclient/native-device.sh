#!/bin/sh
# Bounded temporary checkpoint only. No packages, routing or system services are changed.
set -eu
test "$#" -eq 1
driver=$(readlink -f "$0")
work=$(readlink -f "$1")
case "$work" in /tmp/lc-native-*) ;; *) echo 'Expected a dedicated test directory' >&2; exit 2;; esac
cd "$work"
test ! -e device-state.json
sha256sum -c device.sha256
expected_driver=$(awk '$2 == "native-device.sh" {print $1}' device.sha256)
test -n "$expected_driver"
test "$(sha256sum "$driver" | awk '{print $1}')" = "$expected_driver"
. ./settings.sh
test "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$EXPECTED_BOOT"
cp /proc/sys/kernel/random/boot_id boot-before
cat /tmp/sysinfo/board_name > board-name
ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-before
find /etc/config -type f -exec sha256sum '{}' \; | sort > configuration-before
chmod 700 lc-tunnel.native reference.native
export SSL_CERT_FILE="$work/ca.pem"
unset GOGC GOMEMLIMIT GOMAXPROCS GODEBUG
started=$(cut -d. -f1 /proc/uptime)
pid= monitor= phases=0 deadline_exceeded=false cleanup_exit=0
now() { cut -d. -f1 /proc/uptime; }
control() {
    test "$(curl -fsS --noproxy '*' --connect-timeout 3 --max-time 10 -X POST \
        -H "Authorization: Bearer $CONTROL_TOKEN" "$CONTROL_URL/$1")" = READY
}
alive() { test -n "$pid" && kill -0 "$pid" 2>/dev/null; }
stop_child() {
    if alive; then
        kill -TERM "$pid" 2>/dev/null || true
        n=0
        while alive && test "$n" -lt 15; do sleep 1; n=$((n + 1)); done
        if alive; then kill -KILL "$pid"; cleanup_exit=1; fi
    fi
}
finish() {
    status=$?
    trap - EXIT HUP INT TERM
    if test "$status" -ne 0; then control abort >/dev/null 2>&1 || true; fi
    stop_child
    if test -n "$pid"; then wait "$pid" 2>/dev/null || true; fi
    if test -n "$monitor"; then kill "$monitor" 2>/dev/null || true; wait "$monitor" 2>/dev/null || true; fi
    test ! -e deadline-exceeded || deadline_exceeded=true
    cp /proc/sys/kernel/random/boot_id boot-after
    ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-after
    find /etc/config -type f -exec sha256sum '{}' \; | sort > configuration-after
    elapsed=$(($(now) - started))
    printf '{"exit_code":%s,"cleanup_exit":%s,"phases_completed":%s,"deadline_exceeded":%s,"elapsed_seconds":%s}\n' \
        "$status" "$cleanup_exit" "$phases" "$deadline_exceeded" "$elapsed" > device-state.json
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
sample() {
    available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    rss=$(awk '/VmRSS:/ {print $2}' "/proc/$pid/status")
    threads=$(awk '/Threads:/ {print $2}' "/proc/$pid/status")
    fds=$(ls "/proc/$pid/fd" | wc -l)
    elapsed=$(($(now) - started))
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$elapsed" "$available" "$rss" "$fds" "$threads" >> resources.tsv
    if test "$elapsed" -ge 1200; then
        touch deadline-exceeded
        kill -TERM "$pid" 2>/dev/null || true
        return 1
    fi
}
ready() {
    port_hex=$(printf '%04X' "$port")
    inodes=$(awk -v p=":$port_hex" '$2 ~ (p "$") && $4 == "0A" {print $10}' /proc/net/tcp /proc/net/tcp6)
    for inode in $inodes; do
        for fd in /proc/"$pid"/fd/*; do
            test "$(readlink "$fd" 2>/dev/null)" != "socket:[$inode]" || return 0
        done
    done
    return 1
}
control ready
while IFS="$(printf '\t')" read -r id round role scenario; do
    test "$(($(now) - started))" -lt 1200
    control "phase/$id/start"
    binary=reference.native port=19990
    if test "$role" = lc; then
        binary=lc-tunnel.native port=19991
        ./lc-tunnel.native fingerprint.fpt "$SERVER_ADDRESS" "$SERVER_PORT" "$SERVER_NAME" \
            "$WRONG_KEY" "$SHORT_ID" "$UUID" "$port" -t 127.0.0.1:18080 -f xtls-rprx-vision -w 1 > "$id.log" 2>&1 &
    else
        ./reference.native client.pb > "$id.log" 2>&1 &
    fi
    pid=$!
    observed_from=$(($(now) - started))
    sample
    (while alive; do sample || exit 1; sleep 1; done) & monitor=$!
    # Hashing the Go executable takes seconds on MIPS; monitor startup as well.
    binary_hash=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
    test "$binary_hash" = "$(sha256sum "$binary" | awk '{print $1}')"
    n=0
    until ready; do alive; test "$n" -lt 10; sleep 1; n=$((n + 1)); done
    sleep 2
    alive
    cat "/proc/$pid/stat" > "$id.stat-before"
    probe=0
    curl -sS --noproxy '*' --connect-timeout 3 --max-time 30 "http://127.0.0.1:$port/" > "$id.probe.log" 2>&1 || probe=$?
    printf '%s\n' "$probe" > "$id.probe-exit"
    case "$probe" in 52|56) ;; *) exit 1;; esac
    sleep 6
    alive
    test ! -e deadline-exceeded
    cat "/proc/$pid/stat" > "$id.stat-after"
    observed_until=$(($(now) - started))
    kill "$monitor" 2>/dev/null || true
    monitor_exit=0
    wait "$monitor" 2>/dev/null || monitor_exit=$?
    monitor=
    test "$monitor_exit" -eq 143
    stop_child
    client_exit=0
    wait "$pid" || client_exit=$?
    pid=
    expected=0
    test "$role" != lc || expected=143
    test "$client_exit" -eq "$expected"
    test "$cleanup_exit" -eq 0
    printf '{"phase_id":%s,"binary_sha256":"%s","alive_before_probe":true,"alive_after_probe":true,"probe_exit":%s,"stop_signal":15,"client_exit":%s,"monitor_exit":%s,"observed_from_seconds":%s,"observed_until_seconds":%s}\n' \
        "$id" "$binary_hash" "$probe" "$client_exit" "$monitor_exit" "$observed_from" "$observed_until" > "$id.json"
    control "phase/$id/complete"
    phases=$((phases + 1))
    printf 'NATIVE_PHASE_COMPLETE %s\n' "$id"
done < phases.tsv
test "$phases" -eq 24
test ! -e deadline-exceeded
cmp boot-before /proc/sys/kernel/random/boot_id
control finish
