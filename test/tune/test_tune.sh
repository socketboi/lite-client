#!/bin/sh
# The TCP memory the init script gives the kernel, computed and read back.
#
# WHY THIS EXISTS. lc_tune_tcp writes three kernel settings for the whole router on every start, and
# what can go wrong with it does not look like an error: raising from its own previous value on every
# restart (times three, then nine, then twenty-seven), a threshold past half of the memory that is free
# (four downloads at once then take the box down to its last megabytes — measured, 24.09), a socket
# ceiling past the 32 MB the planes use, a refusal from the kernel that stops the tunnel from starting,
# or a bad reading kept as "the kernel's sizing" so that no start sizes anything until a reboot. Each
# would pass `sh -n`.
#
# HOW. As in test/rules: the real function is CUT OUT of the real init script and evaluated here, with
# `sysctl` and `logger` replaced by stubs and /proc/meminfo by a file, so that what it would write can
# be read. The numbers are the two boxes it was measured on — the AX3000T (tcp_mem 2760 3681 5520, the
# REALITY plane's 32 MB buffers, ~60 MB free beside AdGuard Home and sing-box) and the MT7621 router
# temp (1353 1804 2706, the kernel's own 0.9 MB, ~40 MB free).
set -u

# Overridable so that a mutated COPY can be checked; the gate uses the real file.
INIT=${LC_INIT:-package/files/lite-client.init}
fails=0

ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

[ -f "$INIT" ] || { bad "$INIT not found — the TCP sizing was NOT checked"; exit 1; }

extract() {
    _s=$(grep -n "^$1() {" "$INIT" | head -1 | cut -d: -f1)
    if [ -z "$_s" ]; then
        bad "could not find $1() in $INIT — the TCP sizing was NOT checked"
        exit 1
    fi
    _e=$(awk -v s="$_s" 'NR>s && $0=="}" {print NR; exit}' "$INIT")
    if [ -z "$_e" ]; then
        bad "could not find the end of $1() — the TCP sizing was NOT checked"
        exit 1
    fi
    awk -v s="$_s" -v e="$_e" 'NR>=s && NR<=e' "$INIT"
}

eval "$(extract lc_is_number)"
eval "$(extract lc_tune_tcp)"

TCP_MEM_BOOT=${TMPDIR:-/tmp}/lc-tcp-mem.$$
LC_MEMINFO=${TMPDIR:-/tmp}/lc-meminfo.$$
trap 'rm -f "$TCP_MEM_BOOT" "$LC_MEMINFO"' EXIT

# The box's free memory, as /proc/meminfo writes it. Empty argument = no MemAvailable line at all.
free_kb() {
    { printf 'MemTotal:         239024 kB\nMemFree:           41000 kB\n'
      [ -n "$1" ] && printf 'MemAvailable:   %8s kB\n' "$1"
      printf 'Buffers:            1000 kB\n'; } > "$LC_MEMINFO"
}

# The kernel, as three variables. Tabs between the fields, as /proc prints them.
T='	'
K_MEM=""; K_RMEM=""; K_WMEM=""
WROTE=""; REFUSE=0; LOG=""
# shellcheck disable=SC2317
sysctl() {
    case "$1" in
    -n)
        case "$2" in
        net.ipv4.tcp_mem)  [ -n "$K_MEM" ] && printf '%s\n' "$K_MEM" ;;
        net.ipv4.tcp_rmem) [ -n "$K_RMEM" ] && printf '%s\n' "$K_RMEM" ;;
        net.ipv4.tcp_wmem) [ -n "$K_WMEM" ] && printf '%s\n' "$K_WMEM" ;;
        esac
        return 0
        ;;
    -w)
        shift
        [ "$REFUSE" = 1 ] && return 1
        for kv in "$@"; do
            WROTE="$WROTE
$kv"
            case "$kv" in
            net.ipv4.tcp_mem=*)  K_MEM=${kv#*=} ;;
            net.ipv4.tcp_rmem=*) K_RMEM=${kv#*=} ;;
            net.ipv4.tcp_wmem=*) K_WMEM=${kv#*=} ;;
            esac
        done
        return 0
        ;;
    esac
    return 1
}
# shellcheck disable=SC2317
logger() { LOG="$LOG
$*"; }

start() {
    WROTE=""; LOG=""
    lc_tune_tcp
    rc=$?
}
wrote() { printf '%s\n' "$WROTE" | grep -qxF "$1"; }
said()  { printf '%s\n' "$LOG" | grep -qF "$1"; }
shown() { printf '%s' "$WROTE" | grep "$1=" | tr '\n' ' '; }

AX_MEM="2760${T}3681${T}5520"; AX_BUF="4096${T}131072${T}33554432"
RT_MEM="1353${T}1804${T}2706"; RT_RBUF="4096${T}131072${T}923744"; RT_WBUF="4096${T}16384${T}923744"

# --- AX3000T with plenty free (lite-client in sing-box's place): times three --------------------
rm -f "$TCP_MEM_BOOT"
K_MEM=$AX_MEM; K_RMEM=$AX_BUF; K_WMEM=$AX_BUF; free_kb 200000
start
[ "$rc" = 0 ] && ok "a start returns 0" || bad "a start returned $rc"
# 11043 = 3681 * 3; low and high at the kernel's proportions, 3/4 and 3/2 of it.
wrote "net.ipv4.tcp_mem=8282 11043 16564" \
    && ok "AX3000T, 200 MB free: the threshold is the kernel's own times three (11043), 3/4 and 3/2 around it" \
    || bad "AX3000T, 200 MB free: $(shown net.ipv4.tcp_mem)"
wrote "net.ipv4.tcp_rmem=4096 131072 22616064" && wrote "net.ipv4.tcp_wmem=4096 131072 22616064" \
    && ok "AX3000T: a socket may grow to half the threshold (22616064); min and default kept" \
    || bad "AX3000T: buffers $(shown 'net.ipv4.tcp_[rw]mem')"
said "the kernel's own sizing x3" && ok "and the log says which bound decided it" || bad "the log said: $LOG"

# --- a restart, the raised values now in the kernel: sized from the boot reading, not compounded ---
start
wrote "net.ipv4.tcp_mem=8282 11043 16564" \
    && ok "a restart sizes from the value kept at boot, not from its own previous raise" \
    || bad "a restart wrote: $(shown net.ipv4.tcp_mem) (compounding on every restart)"

# --- AX3000T as measured, ~60 MB free beside AdGuard Home and sing-box: half of what is free ------
free_kb 60000
start
# 60000 kB = 15000 pages; half is 7500, under times three (11043).
wrote "net.ipv4.tcp_mem=5625 7500 11250" \
    && ok "AX3000T, 60 MB free: the threshold is half of what is free (7500 pages), not times three" \
    || bad "AX3000T, 60 MB free: $(shown net.ipv4.tcp_mem)"
wrote "net.ipv4.tcp_rmem=4096 131072 15360000" \
    && ok "and a socket gets half of that (15360000)" \
    || bad "AX3000T, 60 MB free: $(shown net.ipv4.tcp_rmem)"
said "half of the 60000 kB free" && ok "and the log names the free memory as the bound" || bad "the log said: $LOG"

# --- MT7621 router, ~40 MB free: half of what is free, just under times three --------------------
rm -f "$TCP_MEM_BOOT"
K_MEM=$RT_MEM; K_RMEM=$RT_RBUF; K_WMEM=$RT_WBUF; free_kb 40000
start
wrote "net.ipv4.tcp_mem=3750 5000 7500" \
    && ok "MT7621, 40 MB free: 5000 pages, half of what is free, just under times three (5412)" \
    || bad "MT7621, 40 MB free: $(shown net.ipv4.tcp_mem)"
wrote "net.ipv4.tcp_rmem=4096 131072 10240000" && wrote "net.ipv4.tcp_wmem=4096 16384 10240000" \
    && ok "MT7621: sockets from 0.9 MB to 10 MB, each side keeping its own default" \
    || bad "MT7621: buffers $(shown 'net.ipv4.tcp_[rw]mem')"

# --- MT7621 with more free: times three is the ceiling, whatever is free -------------------------
free_kb 100000
start
wrote "net.ipv4.tcp_mem=4059 5412 8118" \
    && ok "MT7621, 100 MB free: times three (5412) stays the ceiling — the values measured there, 66-69 Mbit/s" \
    || bad "MT7621, 100 MB free: $(shown net.ipv4.tcp_mem)"

# --- too little free: nothing raised, not even the sockets ----------------------------------------
free_kb 12000
start
# 12000 kB = 3000 pages; half is 1500, under the kernel's own 1804.
[ "$rc" = 0 ] && [ -z "$WROTE" ] \
    && ok "12 MB free: nothing is written — not tcp_mem, not the sockets — and the start goes on" \
    || bad "12 MB free: rc $rc, wrote: $WROTE"
said "too little to raise TCP memory" && ok "and it is said" || bad "too little free was not said: $LOG"

# --- a large box: the socket ceiling stops at the planes' 32 MB -----------------------------------
rm -f "$TCP_MEM_BOOT"
K_MEM="46000${T}61000${T}92000"; K_RMEM=$AX_BUF; K_WMEM=$AX_BUF; free_kb 4000000
start
wrote "net.ipv4.tcp_rmem=4096 131072 33554432" \
    && ok "on a large box a socket stops at 32 MB, the ceiling the planes use" \
    || bad "large box: $(shown net.ipv4.tcp_rmem)"

# --- buffers that do not read as numbers: the kernel's usual min and default ----------------------
rm -f "$TCP_MEM_BOOT"
K_MEM=$RT_MEM; K_RMEM=""; K_WMEM="garbage"; free_kb 100000
start
wrote "net.ipv4.tcp_rmem=4096 131072 11083776" && wrote "net.ipv4.tcp_wmem=4096 16384 11083776" \
    && ok "an unreadable tcp_rmem or tcp_wmem falls back to the kernel's usual min and default" \
    || bad "unreadable buffers: $(shown 'net.ipv4.tcp_[rw]mem')"

# --- no MemAvailable to read: nothing raised, and said --------------------------------------------
rm -f "$TCP_MEM_BOOT"
K_MEM=$RT_MEM; K_RMEM=$RT_RBUF; K_WMEM=$RT_WBUF; free_kb ""
start
[ "$rc" = 0 ] && [ -z "$WROTE" ] && said "cannot read MemAvailable" \
    && ok "no MemAvailable: nothing is written, it is said, and the start goes on" \
    || bad "no MemAvailable: rc $rc, wrote: $WROTE, said: $LOG"

# --- tcp_mem that does not read as numbers: nothing written, nothing kept, the start goes on ------
# Not an empty answer — an empty file is read again by the next start anyway — but text, which, kept,
# would be "the kernel's sizing" to every start until a reboot, and none of them would size anything.
rm -f "$TCP_MEM_BOOT"
K_MEM="n/a"; free_kb 100000
start
[ "$rc" = 0 ] && [ -z "$WROTE" ] \
    && ok "tcp_mem unreadable: nothing is written and the start goes on" \
    || bad "tcp_mem unreadable: rc $rc, wrote: $WROTE"
[ ! -e "$TCP_MEM_BOOT" ] && ok "and the bad reading is not kept as the kernel's sizing" \
    || bad "an unreadable tcp_mem left $TCP_MEM_BOOT behind: $(cat "$TCP_MEM_BOOT")"
said "cannot read net.ipv4.tcp_mem" && ok "and it is said" || bad "unreadable tcp_mem was not said: $LOG"
K_MEM=$RT_MEM
start
wrote "net.ipv4.tcp_mem=4059 5412 8118" \
    && ok "the next start, reading properly, sizes as usual" \
    || bad "after an unreadable tcp_mem the next start wrote: $(shown net.ipv4.tcp_mem)"

# --- the kernel refuses: said, and the tunnel still starts ----------------------------------------
rm -f "$TCP_MEM_BOOT"
K_MEM=$RT_MEM; K_RMEM=$RT_RBUF; K_WMEM=$RT_WBUF; free_kb 100000
REFUSE=1
start
REFUSE=0
[ "$rc" = 0 ] && said "the kernel refused the TCP memory sizing" \
    && ok "a kernel that refuses is said, and is no reason to stay down" \
    || bad "a refusal gave rc $rc and the log: $LOG"

# --- and the call is there, after every refusal and before the tunnel -----------------------------
# The last `return 1` of start_service BEFORE the tunnel starts: the ones after procd_open_instance
# belong to the rules going up, which is later still. index() rather than a regex, for busybox awk.
_call=$(grep -n '^	lc_tune_tcp$' "$INIT" | head -1 | cut -d: -f1)
_open=$(grep -n '^	procd_open_instance$' "$INIT" | head -1 | cut -d: -f1)
_last=$(awk -v o="${_open:-0}" 'index($0, "start_service() {") == 1 {s = 1}
    s && NR < o && index($0, "return 1") {n = NR} END {print n}' "$INIT")
if [ -n "$_call" ] && [ -n "$_open" ] && [ -n "$_last" ] && [ "$_call" -lt "$_open" ] && [ "$_call" -gt "$_last" ]; then
    ok "start_service calls it past its last refusal and before the tunnel starts"
else
    bad "lc_tune_tcp is called at line ${_call:-nowhere}; last refusal ${_last:-?}, procd_open_instance ${_open:-?}"
fi
grep -q '^LC_MEMINFO=/proc/meminfo$' "$INIT" \
    && ok "and on a router the free memory comes from /proc/meminfo" \
    || bad "LC_MEMINFO is not /proc/meminfo in $INIT"

[ "$fails" = 0 ] || exit 1
exit 0
