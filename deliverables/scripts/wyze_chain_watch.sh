#!/bin/bash
# Wyze chain watcher — closes the loop the moment a CAMERA fetches the capsule.
#
# Trigger condition (the chain completing): a GET for 4.52.17.99.tar (or .32)
# from 192.168.4.39/51 in /tmp/ota/forge.log, followed by installer backups on
# 444-449, a beacon, or an open shell port. On ANY of those:
#   1. append to the wait ledger (observed),
#   2. run root_proof.py for every plausible vector,
#   3. append an evidence note to fss-p5e9p.
#
# Run from launchd/agent or a login shell; 60s cadence; exit only on proof.
set -u
FORGE_LOG=/tmp/ota/forge.log
BROKER_LOG=/tmp/ota/broker.log
BACKUP_LOG=/tmp/ota/backup.log
BEACON_LOG=/tmp/fss_beacons.log
STATE=/tmp/wyze_chain_watch.state
PROOF=/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts/root_proof.py
PY=/opt/homebrew/bin/python3

log() { echo "$(date '+%H:%M:%S') $*"; }

# marker: camera-sourced capsule GET not yet counted
base=$(grep -cE '192\.168\.4\.(39|51).*GET.*(4\.52\.17\.99|4\.52\.17\.32)\.tar' "$FORGE_LOG" 2>/dev/null)
[ -n "$base" ] || base=0
echo "$base" > "$STATE"
log "armed: baseline camera-capsule GETs = $base"

while :; do
  sleep 60
  now=$(grep -cE '192\.168\.4\.(39|51).*GET.*(4\.52\.17\.99|4\.52\.17\.32)\.tar' "$FORGE_LOG" 2>/dev/null)
  [ -n "$now" ] || now=0
  prev=$(cat "$STATE" 2>/dev/null)
  [ -n "$prev" ] || prev=0
  if [ "$now" -gt "$prev" ]; then
    log "*** CAMERA FETCHED THE CAPSULE ($prev -> $now) ***"
    grep -E '192\.168\.4\.(39|51).*GET.*tar' "$FORGE_LOG" | tail -3
    echo "$now" > "$STATE"

    # ledger: the wait is OBSERVED
    $PY "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts/wait_ledger.py" record \
      --cam "wyze-.39/.51" --expectation "assis GET for 4.52.17.99.tar from camera IP" \
      --state observed --observations "$now" \
      --note "chain completed; capture started $(date '+%F %T')" 2>/dev/null

    # give the installer a moment, then capture every proof vector
    sleep 30
    for cam in 192.168.4.39 192.168.4.51; do
      for vec in telnet9999 dropbear22 beacon-uid0; do
        $PY "$PROOF" "$cam" "$vec" --timeout 4 >> /tmp/wyze_chain_proof.log 2>&1 || true
      done
    done
    log "proof sweep done -> /tmp/wyze_chain_proof.log, deliverables/proofs/LEDGER.md"
  fi

  # secondary triggers worth proving even without a fresh GET
  if grep -qE 'received: \[\(444, [1-9]' "$BACKUP_LOG" 2>/dev/null && [ ! -f /tmp/wyze_backups_seen ]; then
    log "*** INSTALLER BACKUPS LANDED (444-449 non-zero) ***"
    touch /tmp/wyze_backups_seen
    for cam in 192.168.4.39 192.168.4.51; do
      $PY "$PROOF" "$cam" telnet9999 --timeout 4 >> /tmp/wyze_chain_proof.log 2>&1 || true
    done
  fi
done
