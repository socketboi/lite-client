#!/bin/sh
# Run only a temporary client; never install assets or change router networking.
set -eu
work=$(readlink -f "$1")
phase=$2
case "$work" in /tmp/lc-integration.*) ;; *) exit 2;; esac
case "$phase" in reality-plain|reality-tls|hysteria-plain|hysteria-tls|reality-denied|hysteria-denied) ;; *) exit 2;; esac
cd "$work"
test "$(cat /tmp/sysinfo/board_name)" = xiaomi,mi-router-4a-gigabit
test ! -e "$phase.pid"
target=29602
case "$phase" in *-tls) target=29603;; esac
identity=uuid
secret=auth
case "$phase" in reality-denied) identity=wrong-uuid;; hysteria-denied) secret=wrong-auth;; esac
pid=
birth=
stop_client() {
    if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
        # setsid gives this owned test its own process group. Guard against PID reuse.
        current=$(awk '{print $22}' "/proc/$pid/stat")
        if [ "$current" = "$birth" ]; then
            kill -TERM "-$pid" 2>/dev/null || true
            for unused in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
            if kill -0 "$pid" 2>/dev/null; then kill -KILL "-$pid" 2>/dev/null || true; fi
        fi
    fi
}
trap stop_client EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
case "$phase" in
    reality-*)
        setsid sh -c 'ulimit -c 0; ulimit -v 393216; exec "$@"' -- \
            ./lc-tunnel.hy0 ./firefox.fpt "$NODE" 29600 donor.test "$PUBLIC_KEY" "$SHORT_ID" "@$work/$identity" 29700 \
            -f xtls-rprx-vision -t "127.0.0.1:$target" -u 29701@127.0.0.1:29605 > "$phase.client.log" 2>&1 &
        ;;
    hysteria-*)
        setsid sh -c 'ulimit -c 0; ulimit -v 393216; exec "$@"' -- \
            ./lc-tunnel.hy1 -H "$NODE" 29601 donor.test "@$work/$secret" - 29700 \
            -t "127.0.0.1:$target" -u 29701@127.0.0.1:29605 -p "$PIN" > "$phase.client.log" 2>&1 &
        ;;
esac
pid=$!
birth=$(awk '{print $22}' "/proc/$pid/stat")
printf '%s\n' "$pid" > "$phase.pid"
start=$(date +%s)
printf 'seconds,available_kib,rss_sum_kib,fd_sum,processes,cpu_ticks\n' > "$phase.metrics.csv"
limit=0
while kill -0 "$pid" 2>/dev/null; do
    descendants="$pid"
    frontier=$pid
    while [ -n "$frontier" ]; do
        next=
        for parent in $frontier; do
            children=$(awk -v parent="$parent" '$4 == parent {print $1}' /proc/[0-9]*/stat 2>/dev/null || true)
            next="$next $children"
        done
        frontier=$(printf '%s' "$next" | xargs)
        descendants="$descendants $frontier"
    done
    rss=0
    fds=0
    count=0
    ticks=0
    for task in $descendants; do
        test -r "/proc/$task/status" || continue
        memory=$(awk '/VmRSS:/ {n=$2} END {print n+0}' "/proc/$task/status" 2>/dev/null) || memory=0
        cpu=$(awk '{print $14+$15}' "/proc/$task/stat" 2>/dev/null) || cpu=0
        descriptors=$(ls "/proc/$task/fd" 2>/dev/null | wc -l)
        rss=$((rss+memory))
        ticks=$((ticks+cpu))
        fds=$((fds+descriptors))
        count=$((count+1))
    done
    elapsed=$(($(date +%s)-start))
    available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    printf '%s,%s,%s,%s,%s,%s\n' "$elapsed" "$available" "$rss" "$fds" "$count" "$ticks" >> "$phase.metrics.csv"
    if [ "$available" -lt 4096 ] || [ "$rss" -gt 32768 ] || [ "$elapsed" -ge 900 ]; then
        limit=1
        printf 'RESOURCE_LIMIT available=%s rss_sum=%s elapsed=%s\n' "$available" "$rss" "$elapsed" > "$phase.limit"
        break
    fi
    if [ -e "$phase.finish" ]; then break; fi
    sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
    # REALITY's supervisor owns no traffic; collect every owned worker's summary.
    kill -USR1 "-$pid" 2>/dev/null || true
    sleep 1
fi
stop_client
status=0
wait "$pid" || status=$?
pid=
printf '%s\n' "$status" > "$phase.exit"
printf 'CLIENT_DONE phase=%s exit=%s resource_limit=%s\n' "$phase" "$status" "$limit"
test "$limit" -eq 0
case "$phase" in hysteria-denied) test "$status" -eq 1;; *) test "$status" -eq 0 || test "$status" -eq 143;; esac
