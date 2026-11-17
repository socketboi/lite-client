#!/bin/sh
# Opt-in laboratory workload: native service plus real DNS/nft policy consumers.
# Inputs and copied runtime paths belong to a dedicated, private staging directory.
set -eu
test "$#" -eq 1
driver=$(readlink -f "$0")
b=$(readlink -f "$1")
case "$b" in /tmp/lc-policy-*) ;; *) exit 2 ;; esac
cd "$b"
chmod 700 "$b"
umask 077
test ! -e result.json
sha256sum -c device.sha256 > input-check.log
expected_driver=$(awk '$2 == "native-policy-soak.sh" {print $1}' device.sha256)
test -n "$expected_driver"
test "$(sha256sum "$driver" | awk '{print $1}')" = "$expected_driver"
. ./settings.sh
test "$LAB_ROUTER_ACK" = 1
test "$(cat /tmp/sysinfo/board_name)" = "$EXPECTED_BOARD"
test "$(sha256sum /usr/sbin/lc-tunnel | awk '{print $1}')" = "$CLIENT_SHA"
test "$(sha256sum /etc/init.d/lite-client | awk '{print $1}')" = "$SERVICE_SHA"
exec 8>/var/run/lc-native-lab.lock
flock -n 8 || exit 75
test "$ACTIVE_SECONDS" -ge 60
mkdir -p "$b/state" "$b/run" "$b/dns"
export INSTALL_DIR="$b/state" LC_POLICY_WORK="$b"
# Only namespace/path substitutions: policy implementation remains unchanged.
sed "s|p4vpn|lc_policy_soak|g;s|/var/run/|$b/run/|g;s|/etc/init.d/dnsmasq|$b/dns-service|g;s|/tmp/dnsmasq.d|$b/dns|g" \
    router-lib.sh > runtime.sh
. ./runtime.sh
# Count actual unique selected owners before creating resolvers or changing UCI.
jq -Rne "$DOMAIN_POLICY_JSON_JQ"'
    [inputs] as $names | ($names|length)>=1375 and
    all($names[];domain_name) and ($names|length)==($names|unique|length)
' domains-base >/dev/null
cp -p /etc/config/lite-client original.uci
find /etc/config -type f -exec sha256sum '{}' \; | sort > config-before
sha256sum /etc/dropbear/dropbear_*_host_key > hostkeys-before
cat /proc/sys/kernel/random/boot_id > boot-before
ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-before
observe_environment() {
    dmesg > "$b/oom-current.raw" || return 1
    awk '/oom-killer|oom-kill:|Out of memory:|Killed process/' "$b/oom-current.raw" > "$b/oom-$1.summary" || return 1
    rm "$b/oom-current.raw" || return 1
    # Called before creating the private resolvers and after their cleanup.
    # Birth times distinguish an original DNS daemon from a reused PID.
    : > "$b/owner-dns-current.raw" || return 1
    for dns_pid in $(pidof dnsmasq); do
        awk -v pid="$dns_pid" '{print pid " " $22}' "/proc/$dns_pid/stat" >> "$b/owner-dns-current.raw" || return 1
    done
    sort "$b/owner-dns-current.raw" > "$b/owner-dns-$1.summary" || return 1
    rm "$b/owner-dns-current.raw"
}
observe_environment before
test ! -e /etc/rc.d/S95lite-client
test ! -d "$INSTALL_DIR/domain-transaction"
if nft list table inet lc_policy_soak >/dev/null 2>&1; then exit 2; fi
loads=''; monitor=''; traffic=''; dnsload=''; finished=0
now() { cut -d. -f1 /proc/uptime; }
terminate_tree() {
    # OpenWrt kernels need not expose task/children; PPid is available in status.
    for child in $(awk -v parent="$1" '/^Pid:/ {pid=$2} /^PPid:/ {if($2==parent) print pid}' /proc/[0-9]*/status 2>/dev/null || :); do
        terminate_tree "$child"
    done
    kill "$1" 2>/dev/null || :
}
finish() {
    rc=$?
    trap - EXIT HUP INT TERM
    clean=0
    touch "$b/stop"
    for child in $loads $traffic $dnsload $monitor; do
        terminate_tree "$child"
    done
    for child in $loads $traffic $dnsload $monitor; do wait "$child" 2>/dev/null || :; done
    lite_client_stop || clean=1
    lite_client_disable || clean=1
    [ ! -x "$b/dns-service" ] || "$b/dns-service" stop || clean=1
    if [ -s "$b/upstream.pid" ]; then kill "$(cat "$b/upstream.pid")" || clean=1; fi
    if nft list table inet lc_policy_soak >/dev/null 2>&1; then nft delete table inet lc_policy_soak || clean=1; fi
    observe_environment after || clean=1
    find /etc/config -type f -exec sha256sum '{}' \; | sort > config-after
    sha256sum /etc/dropbear/dropbear_*_host_key > hostkeys-after
    cat /proc/sys/kernel/random/boot_id > boot-after
    ip -o link show | sed 's/^[0-9]*: //;s/:.*//' | sort > interfaces-after
    for name in hostkeys boot interfaces; do cmp "$name-before" "$name-after" || clean=1; done
    /etc/init.d/uhttpd running || clean=1
    printf '{"exit":%s,"cleanup":%s,"finished":%s,"profile_retained":true}\n' "$rc" "$clean" "$finished" > result.json
    files='result.json input-check.log config-before config-after hostkeys-before hostkeys-after boot-before boot-after interfaces-before interfaces-after'
    for file in *.jsonl *.tsv *.sha256 *.log *.summary *.policy.json *.kernel.json; do [ ! -f "$file" ] || files="$files $file"; done
    tar -czf results.tgz $files
    command curl -q -fsS --http1.1 --noproxy '*' --connect-timeout 5 --max-time 30 \
        --resolve "hy-soak.test:29664:$PEER" --cacert cert.pem \
        -H "Authorization: Bearer $(cat upload-token)" -T results.tgz \
        https://hy-soak.test:29664/results || clean=1
    printf 'POLICY_SOAK_RESULT exit=%s cleanup=%s finished=%s\n' "$rc" "$clean" "$finished"
    [ "$rc" = 0 ] && [ "$clean" = 0 ] && [ "$finished" = 1 ]
}
trap finish EXIT
trap 'exit 143' HUP TERM
trap 'exit 130' INT
cat > dns-service <<'SERVICE'
#!/bin/sh
set -eu
b=$LC_POLICY_WORK
case "$1" in
 stop)
    [ -s "$b/forward.pid" ] || exit 0
    pid=$(cat "$b/forward.pid")
    tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fx -- "--conf-file=$b/forward.conf" >/dev/null
    kill "$pid"
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        [ -e "$b/forward.pid" ] || exit 0
        sleep 1
    done
    exit 1 ;;
 start) dnsmasq --conf-file="$b/forward.conf" ;;
 restart) "$0" stop; "$0" start ;;
 *) exit 1 ;;
esac
SERVICE
chmod 700 dns-service probe
domain_policy_stopped() { [ ! -e "$b/forward.pid" ]; }
DOMAIN_POLICY_DNS_PORT=1053
DOMAIN_POLICY_READY_TRIES=5
printf 'port=1054\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\nlocal-ttl=600\npid-file=%s/upstream.pid\nlog-facility=%s/upstream.log\n' "$b" "$b" > upstream.conf
cat dns-addresses.conf >> upstream.conf
printf 'port=1053\nlisten-address=0.0.0.0\nbind-interfaces\nno-resolv\nno-hosts\nserver=127.0.0.1#1054\ncache-size=4096\nconf-dir=%s/dns\npid-file=%s/forward.pid\nlog-facility=%s/forward.log\nuser=root\n' "$b" "$b" "$b" > forward.conf
dnsmasq --conf-file="$b/upstream.conf"
route_mark=$(awk '/^FWMARK=0x[0-9A-Fa-f]+$/ {print substr($0,8)}' /etc/init.d/lite-client)
case "$route_mark" in 0x[0-9A-Fa-f]*) ;; *) echo 'invalid installed native routing mark' >&2; exit 1 ;; esac
nft -f - <<NFT
table inet lc_policy_soak {
    set domains_vpn { type ipv4_addr; flags interval; auto-merge; }
    set domains_vpn6 { type ipv6_addr; }
    chain vpn_mangle {}
    chain vpn_forward_guard {}
    chain output { type route hook output priority mangle; policy accept;
        ip daddr @domains_vpn tcp dport 29662 counter meta mark set meta mark | $route_mark
        ip daddr @domains_vpn udp dport 29663 counter meta mark set meta mark | $route_mark
    }
    chain prerouting { type filter hook prerouting priority -151; policy accept;
        ip daddr @domains_vpn tcp dport 29662 counter tproxy ip to :19999 meta mark set meta mark | $route_mark accept
        ip daddr @domains_vpn udp dport 29663 counter tproxy ip to :19998 meta mark set meta mark | $route_mark accept
    }
}
NFT
domain_policy_render policy-seed.json > "$INSTALL_DIR/domain_policy.nft"
domain_policy_initialize
# A frozen warm snapshot can be replayed after a driver failure. Validate and
# render its metadata rather than executing arbitrary supplied nft text.
domain_policy_read > validated-seed.json
domain_policy_render validated-seed.json > validated-seed.nft
{ printf 'table inet lc_policy_soak {\n'; cat validated-seed.nft; printf '}\n'; } > seed-table.nft
nft -f seed-table.nft
cp domains-base domains-current
domain_policy_apply domains-current "$b/dns/policy-domains.conf" > bootstrap.log 2>&1
domain_policy_ready "$b/dns/policy-domains.conf"
if ! jq -e '.initialized==true and (.domains|length)>=1375 and
    all(.domains[]; (.ips|length)>0 and (.ips6|length)>0)' validated-seed.json >/dev/null; then
    for type in A AAAA; do
        while IFS= read -r name; do nslookup "-type=$type" "$name" 127.0.0.1:1053 >/dev/null; done < domains-base
    done
fi
domain_policy_checkpoint
domain_policy_read > warmup.policy.json
jq -e '.initialized==true and (.domains|length)>=1375 and
    all(.domains[]; (.ips|length)>0 and (.ips6|length)>0)' warmup.policy.json >/dev/null
rm warmup.policy.json
# A fault at the canonical commit must roll back with traffic still running.
eval "$(sed -n '/^domain_policy_commit()/,/^}/p' runtime.sh | sed '1s/domain_policy_commit/real_domain_policy_commit/')"
domain_policy_commit() {
    if [ -f "$b/fail-commit" ]; then rm "$b/fail-commit"; return 71; fi
    real_domain_policy_commit "$@"
}
uci set lite-client.main.uuid_file=/etc/lite-client/uuid
uci -q delete lite-client.main.workers || :
uci commit lite-client
printf lite > "$INSTALL_DIR/engine"
fw4() { [ "$1" = reload ]; }
apply_plane_routing() { nft list table inet lc_policy_soak >/dev/null; }
read_api_url() { printf https://fixture.invalid/api; }
read_token() { printf fixture; }
curl() {
    case "$*" in *fixture.invalid/api/router/*-config*) cat "$b/current.response" ;; *) command curl "$@" ;; esac
}
pid_now() { ubus call service list '{"name":"lite-client"}' | jq -er '."lite-client".instances.instance1.pid|select(type=="number" and .>0)'; }
kernel_healthy() {
    # Separate observers must never truncate or remove each other's snapshot.
    _kh_raw=$(mktemp "$b/oom-live.XXXXXX") || return 1
    _kh_summary=$_kh_raw.summary
    _kh_ok=0
    if dmesg > "$_kh_raw" &&
        awk '/oom-killer|oom-kill:|Out of memory:|Killed process/' "$_kh_raw" > "$_kh_summary" &&
        cmp "$b/oom-before.summary" "$_kh_summary" >/dev/null; then
        _kh_ok=1
    else
        [ ! -f "$_kh_summary" ] || cp "$_kh_summary" "$b/oom-live.summary" || :
    fi
    rm -f "$_kh_raw" "$_kh_summary" || return 1
    [ "$_kh_ok" = 1 ] || {
        echo 'Kernel OOM evidence changed or could not be read; stopping the laboratory workload' >&2
        return 1
    }
}
monitor_resources() {
    next_kernel=0
    while [ ! -e "$b/stop" ]; do
        stamp=$(now)
        # A new OOM is a failed workload, even when procd revives its victim.
        if [ "$stamp" -ge "$next_kernel" ]; then
            kernel_healthy || return 1
            next_kernel=$((stamp+10))
        fi
        awk -v stamp="$stamp" '/MemAvailable:/ {print stamp "\t" $2}' /proc/meminfo >> "$b/memory.tsv"
        for entry in /proc/[0-9]*/comm; do
            name=$(cat "$entry" 2>/dev/null) || continue
            case "$name" in lc-tunnel|jq|nft|dnsmasq|curl) ;; *) continue ;; esac
            pid=${entry#/proc/}; pid=${pid%/comm}
            awk -v stamp="$stamp" -v pid="$pid" -v name="$name" '
              /VmRSS:/ {rss=$2} /VmHWM:/ {hwm=$2} /Threads:/ {threads=$2}
              END {if(rss!="") print stamp "\t" pid "\t" name "\t" rss "\t" hwm "\t" threads}' \
                "/proc/$pid/status" 2>/dev/null >> "$b/processes.tsv" || :
        done
        sleep 1
    done
}
monitor_resources & monitor=$!
dns_load() {
    queries=0; failures=0
    while [ ! -e "$b/stop" ] && [ "$(now)" -lt "$deadline" ]; do
        while IFS= read -r name; do
            [ "$(now)" -lt "$deadline" ] || break
            for type in A AAAA; do
                if nslookup "-type=$type" "$name" 127.0.0.1:1053 >/dev/null 2>&1; then :; else failures=$((failures+1)); fi
                queries=$((queries+1))
                printf '%s\t%s\n' "$queries" "$failures" > "$b/$plane.dns.summary"
                # Stock OpenWrt BusyBox sleep accepts integer seconds only.
                [ "$((queries%20))" != 0 ] || sleep 1
            done
        done < "$b/domains-base"
    done
}
traffic_load() {
    burst=0
    while [ "$(now)" -lt "$deadline" ]; do
        [ "$(pid_now)" = "$expected_pid" ]
        [ "$(awk '{print $22}' "/proc/$expected_pid/stat")" = "$expected_birth" ]
        loads=''
        for stream in 1 2 3 4; do
            scheme=http; case "$stream" in 2|4) scheme=https ;; esac
            command curl -q -fsS --http1.1 --noproxy '*' --connect-timeout 20 --max-time 30 \
                --resolve hy-soak.test:29662:127.0.0.10 --cacert "$b/cert.pem" \
                -H 'Connection: close' "$scheme://hy-soak.test:29662/$plane/$burst/$stream" \
                -o "$b/$plane.$stream.body" 2>> "$b/traffic-errors.log" &
            loads="$loads $!"
        done
        # A five-second observer could expire before a valid tunnel dial/handshake.
        # Xray DefaultSystemDialer.Dial permits 16 seconds; QUIC's default
        # total handshake budget is 10 seconds. This is a functional gate.
        "$b/probe" udp 29663 127.0.0.1 20 > "$b/udp-current.json" & loads="$loads $!"
        failed=0
        for child in $loads; do wait "$child" || failed=1; done
        loads=''
        [ "$failed" = 0 ]
        for stream in 1 2 3 4; do
            [ "$(wc -c < "$b/$plane.$stream.body")" = 1048576 ]
            [ "$(sha256sum "$b/$plane.$stream.body" | awk '{print $1}')" = "$BODY_SHA" ]
            sha256sum "$b/$plane.$stream.body" >> "$b/payloads.sha256"
            rm "$b/$plane.$stream.body"
        done
        [ "$(jq -r .echoes "$b/udp-current.json")" = 64 ]
        printf '{"plane":"%s","burst":%s,"uptime":%s,"pid":%s,"birth":"%s","tcp":4,"udp":64}\n' \
            "$plane" "$burst" "$(now)" "$expected_pid" "$expected_birth" >> "$b/traffic.jsonl"
        burst=$((burst+1))
        due=$((phase_start+burst*TRAFFIC_PERIOD))
        while [ "$(now)" -lt "$due" ]; do sleep 1; done
    done
}
present() { nft get element inet lc_policy_soak domains_vpn "{ $1 }" >/dev/null 2>&1; }
check_loads() {
    kill -0 "$traffic" 2>/dev/null || return 1
    kill -0 "$dnsload" 2>/dev/null || return 1
    kill -0 "$monitor" 2>/dev/null || return 1
}
finalize_policy() {
    # Restore the declared selection regardless of timed-operation parity.
    cp "$b/domains-base" "$b/domains-next" || return 1
    domain_policy_apply "$b/domains-next" "$b/dns/policy-domains.conf" >> "$b/policy.log" 2>&1 || return 1
    domain_policy_checkpoint || return 1
    domain_policy_read > "$b/$plane.policy.json" || return 1
    nft -j list table inet lc_policy_soak > "$b/$plane.kernel.json" || return 1
    domain_policy_consistent "$b/$plane.policy.json" "$b/$plane.kernel.json"
}
for plane in hysteria reality; do
    . "$b/plane-$plane.sh"
    plane_hotplug() { return 0; }
    cp "$b/$plane.response" current.response
    plane_prepare_config
    plane_start
    expected_pid=$(pid_now)
    expected_birth=$(awk '{print $22}' "/proc/$expected_pid/stat")
    phase_start=$(now); deadline=$((phase_start+ACTIVE_SECONDS))
    printf '{"plane":"%s","event":"start","uptime":%s,"pid":%s}\n' "$plane" "$phase_start" "$expected_pid" >> phases.jsonl
    traffic_load & traffic=$!
    dns_load & dnsload=$!
    cycle=0; selected=0
    while [ "$(now)" -lt "$((deadline-30))" ]; do
        check_loads
        started=$(now)
        case "$cycle" in
            2)
                cp domains-base domains-next
                [ "$selected" != 0 ] || printf 'toggle.audit.test\n' >> domains-next
                touch fail-commit
                if domain_policy_apply domains-next "$b/dns/policy-domains.conf" >> policy.log 2>&1; then exit 1; else rc=$?; fi
                [ "$rc" = 71 ]
                [ ! -d "$INSTALL_DIR/domain-transaction" ]
                domain_policy_ready "$b/dns/policy-domains.conf"
                if [ "$selected" = 1 ]; then present 127.3.99.1;
                else if present 127.3.99.1; then exit 1; fi; fi
                operation=rollback ;;
            *)
                if [ "$((cycle%2))" = 1 ]; then
                    cp domains-base domains-next
                    if [ "$selected" = 0 ]; then printf 'toggle.audit.test\n' >> domains-next; selected=1; else selected=0; fi
                    domain_policy_apply domains-next "$b/dns/policy-domains.conf" >> policy.log 2>&1
                    if [ "$selected" = 1 ]; then
                        nslookup -type=A toggle.audit.test 127.0.0.1:1053 >/dev/null
                        present 127.3.99.1
                    else if present 127.3.99.1; then exit 1; fi; fi
                    operation=apply
                else
                    domain_policy_checkpoint >> policy.log 2>&1
                    operation=checkpoint
                fi ;;
        esac
        plane_sync >> sync.log 2>&1
        if [ "$(now)" -lt "$deadline" ]; then check_loads; fi
        [ "$(pid_now)" = "$expected_pid" ]
        present 127.0.0.10 && present 127.0.0.1
        printf '{"plane":"%s","cycle":%s,"operation":"%s","start":%s,"end":%s,"pid":%s}\n' \
            "$plane" "$cycle" "$operation" "$started" "$(now)" "$expected_pid" >> policy.jsonl
        echo "POLICY_CYCLE $plane $cycle $operation"
        cycle=$((cycle+1)); due=$((phase_start+cycle*60))
        while [ "$(now)" -lt "$due" ] && [ "$(now)" -lt "$deadline" ]; do sleep 1; done
    done
    wait "$traffic"; traffic=''
    wait "$dnsload"; dnsload=''
    [ "$(now)" -ge "$deadline" ]
    [ "$(pid_now)" = "$expected_pid" ]
    finalize_policy
    printf '{"plane":"%s","event":"end","uptime":%s,"pid":%s}\n' "$plane" "$(now)" "$expected_pid" >> phases.jsonl
    lite_client_stop
    lite_client_disable
    selected=0
    echo "PHASE_COMPLETE $plane"
done
finished=1
