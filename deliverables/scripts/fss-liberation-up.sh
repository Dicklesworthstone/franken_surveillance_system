#!/bin/bash
# fss-liberation-up.sh — the liberation control plane's ONE entry point.
#
# Everything else in this directory is a half: fleet_status.py reads, fleet_reconcile.py
# repairs fleet drift, and the per-camera lanes are launchd jobs. What was missing is the
# single idempotent command that says "every camera of this fleet is armed, right now",
# survives being run twice, and re-arms a lane that died. That is this file.
#
#   fss-liberation-up.sh --plan     # print exactly what would be armed, mutate nothing
#   fss-liberation-up.sh            # arm everything missing, then verify
#   fss-liberation-up.sh --force    # arm even if the readiness gate is dirty
#
# NOTE: `launchctl kickstart -k` does NOT re-read the plist, so an EnvironmentVariables edit is
# invisible to a kickstarted job. Anything that changes a plist env must be booted out and
# bootstrapped — which is what this script does. That trap cost two wrong runs.
#
# Idempotent by construction: a lane that is already loaded (running or spawn-scheduled) is
# left alone — never booted out, never kickstarted, because KeepAlive supervisors fight back
# and a camera session that drops takes 15-30 min of backoff with it. Only missing lanes are
# bootstrapped. Exit code 0 only when every lane is loaded AND the gate is clean.
#
# The gate is fleet_status.py --gate: it is the same truth, so a dirty fleet fails here
# before anything is touched unless --force is given.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LAUNCHD="$ROOT/deliverables/launchd"
STATUS="$ROOT/deliverables/scripts/fleet_status.py"
DOMAIN="system"

PLAN=0; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# Every lane a live fleet needs, in the order a cold host should get them back.
# broker and fwserve first (the Wyze pair and both Tapo lanes fetch through them), then the
# capturing planes, then the per-camera vectors.
LANES=(
  com.jeffreyemanuel.wyze-broker
  com.jeffreyemanuel.wyze-broker-watch
  com.jeffreyemanuel.fss-fwserve
  com.jeffreyemanuel.fss-backup-recv
  com.jeffreyemanuel.wyze-tunnel
  com.jeffreyemanuel.wyze-capsule-serve
  com.jeffreyemanuel.wyze-pf-rdr
  com.jeffreyemanuel.wyze-forge
  com.jeffreyemanuel.wyze-forge-8443
  com.jeffreyemanuel.wyze-rtsp-watch
  com.jeffreyemanuel.wyze-chain-watch
  com.jeffreyemanuel.c460-burst-daemon
  com.jeffreyemanuel.c460-fire
  com.jeffreyemanuel.c660-sweep
  com.jeffreyemanuel.c660-tftp
  com.jeffreyemanuel.c660-convert
  com.jeffreyemanuel.owlet-relay-watch
  com.jeffreyemanuel.yi-listener
  com.jeffreyemanuel.persistent-exploit
  com.jeffreyemanuel.fleet-readiness
)

state_of() { # -> running | scheduled | loaded-other | missing | unplist
  local label=$1
  [ -f "$LAUNCHD/$label.plist" ] || { echo unplist; return; }
  local out
  out=$(sudo -n launchctl print "$DOMAIN/$label" 2>/dev/null) || { echo missing; return; }
  case "$out" in
    *"state = running"*) echo running ;;
    *"state = spawn scheduled"*) echo scheduled ;;
    *) echo loaded-other ;;
  esac
}

armed=0; missing=0; failed=0; unplist=0
for label in "${LANES[@]}"; do
  s=$(state_of "$label")
  case "$s" in
    running|scheduled|loaded-other)
      printf '  ok      %-46s %s\n' "$label" "$s"
      armed=$((armed + 1))
      continue
      ;;
    unplist)
      printf '  NOPLIST %-46s %s\n' "$label" "$LAUNCHD/$label.plist"
      unplist=$((unplist + 1))
      continue
      ;;
  esac
  missing=$((missing + 1))
  if [ "$PLAN" = 1 ]; then
    printf '  ARM     %-46s (enable + bootstrap)\n' "$label"
    continue
  fi
  # a lane booted out (or never enabled) needs enable first; bootstrap takes the INSTALLED
  # plist, which is what launchd resolved originally
  sudo -n launchctl enable "$DOMAIN/$label" 2>/dev/null
  src="/Library/LaunchDaemons/$label.plist"
  [ -f "$src" ] || src="$LAUNCHD/$label.plist"
  if sudo -n launchctl bootstrap "$DOMAIN" "$src" 2>/dev/null; then
    printf '  armed   %-46s (bootstrap)\n' "$label"
  else
    printf '  FAILED  %-46s (bootstrap)\n' "$label"
    failed=$((failed + 1))
  fi
done

echo "-- lanes: $armed have it, $missing were missing, $failed failed, $unplist without plist"

# The gate is the second half of "armed": lanes can be up while a camera plane is down.
if [ "$PLAN" = 1 ]; then
  /opt/homebrew/bin/python3 "$STATUS" --gate >/dev/null 2>&1
  rc=$?
  [ $rc -eq 0 ] && echo "-- gate: clean" || echo "-- gate: DIRTY (a lane is up but a camera plane is down)"
  exit 0
fi

/opt/homebrew/bin/python3 "$STATUS" --gate >/dev/null 2>&1
gate=$?
if [ $gate -ne 0 ]; then
  echo "-- gate: DIRTY after arming"
  /opt/homebrew/bin/python3 "$STATUS" 2>/dev/null | grep -i 'DOWN' | head -10
  if [ "$FORCE" = 0 ] && [ "$failed" -eq 0 ]; then
    echo "   (fleet lanes are armed; camera planes still down — rerun with --force to ignore)"
  fi
fi

[ "$failed" -eq 0 ] && [ "$unplist" -eq 0 ] && [ "$gate" -eq 0 ]
