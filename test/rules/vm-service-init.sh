#!/bin/sh
# Diskless local guest. Do not start the factory rc.d set, SSH or network daemons.
mount -t proc proc /proc
mount -t sysfs sysfs /sys
exec </dev/console >/dev/console 2>&1
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /tmp/run /tmp/lock /tmp/state /opt/vm-rc.d
echo 0 > /proc/sys/kernel/printk
echo "LC_SERVICE_KERNEL $(uname -r)"
# Archives are hash-pinned by the host. This flag explicitly permits their
# installation in an ephemeral initramfs; it is not a production install recipe.
if ! apk --no-network --no-cache --force-non-repository add --allow-untrusted /opt/inputs/*.apk; then
    echo LC_SERVICE_RESULT=1
    poweroff -f
fi
exec /sbin/procd -S -R /opt/vm-rc.d
