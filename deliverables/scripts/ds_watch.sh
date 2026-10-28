#!/bin/bash
# presence watch -> DS enum on return
while true; do
  ping -c 1 -t 1 192.168.4.70 >/dev/null 2>&1
  if arp -n 192.168.4.70 | grep -qv "no entry"; then
    if arp -n 192.168.4.70 | grep -q "50:3d:d1"; then
      echo "PRESENT at $(date +%H:%M:%S)"
      exec /opt/homebrew/bin/python3 /tmp/ds_enum.py
    fi
  fi
  sleep 8
done
