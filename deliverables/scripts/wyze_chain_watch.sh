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
# The camera reaches the capsule through the trycloudflare tunnel, so cloudflared
# connects from 127.0.0.1 and forge.log shows no camera IP. fw_serve_logged.py
# records every request with its User-Agent, and our own probes send fss-probe.
# Camera-sourced = probe:false request for a .tar that either moved bytes or 4xx'd.
ACCESS=/tmp/ota/fwserve_access.jsonl

log() { echo "$(date '+%H:%M:%S') $*"; }

camera_hits() {
  $PY - "$ACCESS" <<'EOF' 2>/dev/null || echo 0
import json, sys
n = 0
try:
    for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("probe") or not r.get("path", "").endswith(".tar"):
            continue
        if r.get("method") == "GET" and (r.get("bytes_sent", 0) > 0 or r.get("status", 0) >= 400):
            n += 1
except FileNotFoundError:
    pass
print(n)
EOF
}

# marker: camera-sourced capsule GET not yet counted
base=$(camera_hits)
case "$base" in ''|*[!0-9]*) base=0 ;; esac
echo "$base" > "$STATE"
log "armed: baseline camera-capsule hits = $base (tunnel access log)"
prev_hits=$base

while :; do
  sleep 60
  now=$(camera_hits)
  case "$now" in ''|*[!0-9]*) now=$prev_hits ;; esac
  prev_hits=$now
  prev=$(cat "$STATE" 2>/dev/null)
  [ -n "$prev" ] || prev=0
  if [ "$now" -gt "$prev" ]; then
    log "*** CAMERA REACHED THE CAPSULE ($prev -> $now) ***"
    grep -v '"probe":true' "$ACCESS" 2>/dev/null | tail -3
    echo "$now" > "$STATE"

    # ledger: the wait is OBSERVED
    $PY "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts/wait_ledger.py" record \
      --cam "wyze-.39/.51" --expectation "camera GET for 4.52.17.99.tar over the trycloudflare tunnel" \
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
