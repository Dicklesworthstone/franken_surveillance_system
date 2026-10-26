#!/bin/sh
# Keep the ARP spoofer honest.
#
# bettercap does not exit when its pcap handle dies; it keeps running and logs
# "arp.spoof error while sending packet: send: Device not configured" forever while the camera
# quietly falls back to the real cloud. KeepAlive cannot see that, so this watchdog reads the log
# and restarts the job when the error rate is non-zero over a fresh window.
#
#   wyze_spoof_watch.sh [interval]
set -u
INTERVAL=${1:-60}
LOG=/tmp/ota/spoof.log
JOB=system/com.jeffreyemanuel.wyze-spoof

while :; do
  sleep "$INTERVAL"
  [ -r "$LOG" ] || continue
  before=$(wc -c < "$LOG" 2>/dev/null || echo 0)
  sleep 10
  after=$(wc -c < "$LOG" 2>/dev/null || echo 0)
  # only the bytes appended in the last 10 s matter
  recent=$(tail -c $((after - before + 1)) "$LOG" 2>/dev/null | grep -c "Device not configured" || true)
  if [ "${recent:-0}" -gt 3 ]; then
    echo "$(date +%H:%M:%S) $recent send errors in 10 s -> kickstart" >>/tmp/ota/spoof-watch.log
    launchctl kickstart -k "$JOB" >>/tmp/ota/spoof-watch.log 2>&1
    sleep 15
  fi
done
