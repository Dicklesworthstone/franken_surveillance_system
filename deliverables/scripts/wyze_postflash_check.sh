#!/bin/sh
# Post-flash identity check for one unit. Stock answers 443/554 with the vendor stack and reports
# firmware_ver in its cloud registration; Thingino answers SSH and an ONVIF/RTSP surface with no
# cloud registration at all.
#   ./wyze_postflash_check.sh 192.168.4.23
IP=${1:?ip}
echo "== ping"; ping -c 2 -W 1000 "$IP" >/dev/null 2>&1 && echo reachable || echo unreachable
echo "== ports"
for p in 22 80 443 554 8554 8080; do
  if nc -z -G 2 "$IP" "$p" 2>/dev/null; then echo "$p open"; else echo "$p closed"; fi
done
echo "== ssh banner"
timeout 4 nc "$IP" 22 2>/dev/null | head -1
echo "== rtsp options"
timeout 4 sh -c "printf 'OPTIONS rtsp://%s:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n' '$IP' | nc $IP 554" 2>/dev/null | head -3
