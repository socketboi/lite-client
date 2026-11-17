#!/bin/sh
# Which `workers` values the init script lets each plane start with.
#
# WHY THIS EXISTS. A Hysteria2 server that sells a subscription as one active session closes each
# earlier session of a password the moment a newer one registers. Several workers each dial their own
# session with that password, so `option workers auto` — the value a REALITY box wants —
# would turn a Hysteria2 box into a tunnel made of 0x107 closes that looks like the path blocking it.
# The script refuses it; this checks the refusal is there, says why, and leaves REALITY alone.
#
# HOW. As in test/rules and test/tune: the real function is CUT OUT of the real init script and
# evaluated here, with `logger` stubbed so that what it says can be read.
set -u

# Overridable so that a mutated COPY can be checked; the gate uses the real file.
INIT=${LC_INIT:-package/files/lite-client.init}
fails=0

ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

[ -f "$INIT" ] || { bad "$INIT not found — workers were NOT checked"; exit 1; }

extract() {
    _s=$(grep -n "^$1() {" "$INIT" | head -1 | cut -d: -f1)
    if [ -z "$_s" ]; then
        bad "could not find $1() in $INIT — workers were NOT checked"
        exit 1
    fi
    _e=$(awk -v s="$_s" 'NR>s && $0=="}" {print NR; exit}' "$INIT")
    if [ -z "$_e" ]; then
        bad "could not find the end of $1() — workers were NOT checked"
        exit 1
    fi
    awk -v s="$_s" -v e="$_e" 'NR>=s && NR<=e' "$INIT"
}

eval "$(extract lc_workers_ok)"

LOG=""
# shellcheck disable=SC2317
logger() { LOG="$LOG
$*"; }

# check PLANE WORKERS EXPECTED(0 starts, 1 refuses) WHAT
check() {
    LOG=""
    lc_workers_ok "$1" "$2"
    rc=$?
    if [ "$rc" = "$3" ]; then ok "$4"; else bad "$4 (returned $rc; said: $LOG)"; fi
}

check reality auto 0 "REALITY starts with workers auto"
check reality 4    0 "REALITY starts with workers 4"
check reality 1    0 "REALITY starts with workers 1"
check reality 9    1 "REALITY refuses workers 9"
check reality many 1 "REALITY refuses a word that is not auto"

check hysteria 1    0 "Hysteria2 starts with workers 1"
check hysteria auto 1 "Hysteria2 refuses workers auto: every worker would be its own session"
printf '%s\n' "$LOG" | grep -q "0x107" && printf '%s\n' "$LOG" | grep -q "one session per subscription" \
    && ok "and says why: the node keeps one session per subscription and closes the rest (0x107)" \
    || bad "the refusal of workers auto on Hysteria2 does not say why: $LOG"
check hysteria 2    1 "Hysteria2 refuses workers 2"
check hysteria 8    1 "Hysteria2 refuses workers 8"
check hysteria 9    1 "Hysteria2 refuses workers 9 as out of range, like REALITY"

# And start_service asks it before -w reaches the command line, and stops when it says no.
_ask=$(grep -n 'lc_workers_ok "\$plane" "\$workers" || return 1' "$INIT" | head -1 | cut -d: -f1)
_pass=$(grep -n 'set -- "\$@" -w "\$workers"' "$INIT" | head -1 | cut -d: -f1)
if [ -n "$_ask" ] && [ -n "$_pass" ] && [ "$_ask" -lt "$_pass" ]; then
    ok "start_service asks lc_workers_ok, and refuses, before -w goes on the command line"
else
    bad "start_service: lc_workers_ok at line ${_ask:-nowhere}, -w added at line ${_pass:-nowhere}"
fi
[ "$(grep -c -- '-w "\$workers"' "$INIT")" = 1 ] \
    && ok "-w is added in that one place only" \
    || bad "-w is added in $(grep -c -- '-w "\$workers"' "$INIT") places; the check guards one"

[ "$fails" = 0 ] || exit 1
exit 0
