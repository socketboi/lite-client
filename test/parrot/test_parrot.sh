#!/bin/sh
# Whether the Hysteria2 plane parrots Chrome's QUIC stack, from the router's config to the wire.
#
# WHY THIS EXISTS. hysteria's client parrots Chrome unless its config says
# quic.disableChromeParrot, since 2.11, and ours has to do the same by default: `option
# chrome_parrot` empty, or absent, is on. Three places decide it — the init script, the command line
# and the connection — and a default that quietly flipped in any one of them would leave a router
# looking like no client that exists, with every test of the parrot itself still green.
#
# HOW. The init script's function is cut out and evaluated, as test/workers and test/tune do; the
# binary is run against a UDP socket standing where the node would be, and the size of its first
# datagram read: 1250, Chrome's (chromeInitialPacketSize, vendor/quic-go/chrome_parrot.go:18-19),
# when it parrots, and 1280, quic-go's own InitialPacketSize, when it does not.
set -u

# Overridable so that a mutated COPY can be checked; the gate uses the real files.
INIT=${LC_INIT:-package/files/lite-client.init}
PROG=${LC_TUNNEL:-build/lc-tunnel}
FIRST=${LC_FIRSTDGRAM:-build/test-firstdgram}
fails=0

ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

[ -f "$INIT" ] || { bad "$INIT not found — the parrot was NOT checked"; exit 1; }

extract() {
    _s=$(grep -n "^$1() {" "$INIT" | head -1 | cut -d: -f1)
    if [ -z "$_s" ]; then
        bad "could not find $1() in $INIT — the parrot was NOT checked"
        exit 1
    fi
    _e=$(awk -v s="$_s" 'NR>s && $0=="}" {print NR; exit}' "$INIT")
    awk -v s="$_s" -v e="$_e" 'NR>=s && NR<=e' "$INIT"
}

eval "$(extract lc_chrome_parrot)"

LOG=""
# shellcheck disable=SC2317
logger() { LOG="$LOG
$*"; }

# check VALUE EXPECTED(on, off or refused)
check() {
    LOG=""
    got=$(lc_chrome_parrot "$1") || got=refused
    if [ "$got" = "$2" ]; then ok "chrome_parrot '$1' is $2"; else bad "chrome_parrot '$1' is $got, not $2"; fi
}

check ''    on
check 1     on
check on    on
check yes   on
check true  on
check 0     off
check off   off
check no    off
check false off
check maybe refused
LOG=""
lc_chrome_parrot maybe >/dev/null
printf '%s\n' "$LOG" | grep -q "not a yes or a no" \
    && ok "and a value that is neither is refused with a line that says so" \
    || bad "the refusal of 'maybe' says nothing: $LOG"

# start_service asks it before -c goes on the command line, and -c off is the only form passed.
_ask=$(grep -n 'chrome_parrot=$(lc_chrome_parrot "$chrome_parrot") || return 1' "$INIT" | head -1 | cut -d: -f1)
_pass=$(grep -n '\[ "\$chrome_parrot" = off \] && set -- "\$@" -c off' "$INIT" | head -1 | cut -d: -f1)
if [ -n "$_ask" ] && [ -n "$_pass" ] && [ "$_ask" -lt "$_pass" ]; then
    ok "start_service normalises chrome_parrot, and refuses, before -c goes on the command line"
else
    bad "start_service: lc_chrome_parrot at line ${_ask:-nowhere}, -c added at line ${_pass:-nowhere}"
fi
[ "$(grep -c -- ' -c ' "$INIT")" = 1 ] \
    && ok "-c is added in that one place only" \
    || bad "-c appears $(grep -c -- ' -c ' "$INIT") times; the check guards one"

# And the binary: its first datagram, where the node would be.
if [ ! -x "$PROG" ] || [ ! -x "$FIRST" ]; then
    bad "$PROG or $FIRST is not built — the wire was NOT checked"
else
    first() { "$FIRST" "$PROG" "$@" | cut -d' ' -f1; }
    d=$(first);        [ "$d" = 1250 ] && ok "no -c: the first Initial is Chrome's 1250 bytes" \
                                       || bad "no -c: the first datagram is $d bytes, not Chrome's 1250"
    d=$(first -c on);  [ "$d" = 1250 ] && ok "-c on: 1250 bytes" || bad "-c on: $d bytes, not 1250"
    d=$(first -c off); [ "$d" = 1280 ] && ok "-c off: quic-go's own 1280 bytes" \
                                       || bad "-c off: $d bytes, not quic-go's 1280"
    "$PROG" -H 127.0.0.1 1 www.example.com password - 1 -c maybe -p - >/dev/null 2>&1
    rc=$?
    [ "$rc" = 2 ] && ok "-c maybe: refused as a configuration error (exit 2)" \
                  || bad "-c maybe: exit $rc, not 2"
fi

[ "$fails" = 0 ] || exit 1
exit 0
