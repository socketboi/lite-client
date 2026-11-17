#!/bin/sh
# Runs as PID 1 in an initramfs guest: no procd, NICs, disks or device credentials.
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
echo 0 > /proc/sys/kernel/printk

finish() {
    echo "LC_VM_RESULT=$1"
    sync
    poweroff -f
    while :; do sleep 1; done
}
fail() { echo "LC_VM_FAILURE $*"; finish 1; }
need() { "$@" || fail "$*"; }

echo "LC_VM_KERNEL $(uname -r)"
need /sbin/kmodloader
echo "LC_VM_IP $(ip -Version)"
echo "LC_VM_NFT $(nft --version)"
. /opt/lite-client.init
logger() { printf 'LC_VM_LOG %s\n' "$*"; }

# One deliberate invalid rule makes the otherwise valid nft batch fail atomically.
FAULT_NFT=0
nft() {
    if [ "$FAULT_NFT" = 1 ] && [ "$*" = '-f -' ]; then
        cat > /tmp/fault.nft
        printf '\nadd rule inet lite_client lc_missing_chain counter\n' >> /tmp/fault.nft
        /usr/sbin/nft -f /tmp/fault.nft
    else
        /usr/sbin/nft "$@"
    fi
}

capture() {
    {
        printf '{"rules4":'; need ip -j rule show
        printf ',"rules6":'; need ip -6 -j rule show
        printf ',"routes4":'; need ip -j route show table all
        printf ',"routes6":'; need ip -6 -j route show table all
        printf ',"nft":'; need nft -j list ruleset
        printf '}\n'
    } > /tmp/state.json
    printf 'LC_VM_STATE %s ' "$1"
    need hexdump -v -e '1/1 "%02x"' /tmp/state.json
    printf '\n'
}

need ip link set lo up
for family in 4 6; do
    need ip "-$family" rule add priority 30001 fwmark 0x50505 lookup 105
    need ip "-$family" route add local default dev lo table 105
done
need nft add table inet lc_vm_foreign
need nft add chain inet lc_vm_foreign retained
need nft add rule inet lc_vm_foreign retained counter
capture baseline

need lc_rules_up 19099 '192.0.2.7' 203.0.113.7 ''
capture tcp
need lc_rules_down
capture tcp-clean

need lc_rules_up 19099 '192.0.2.7 198.51.100.0/24' 203.0.113.7 19098
capture tcp-udp
need lc_rules_up 19099 '192.0.2.7 198.51.100.0/24' 203.0.113.7 19098
capture repeat

need lc_rules_up 19099 '' 2001:db8::7 19098
capture external
need lc_rules_down
need lc_rules_down
capture all-clean

FAULT_NFT=1
if lc_rules_up 19099 '192.0.2.7' 203.0.113.7 19098; then
    fail 'injected nft transaction unexpectedly succeeded'
fi
capture nft-failure
finish 0
