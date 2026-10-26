#!/bin/sh
# Keep the MQTT proxy's upstream honest.
#
# The proxy dials the real AWS with the device's own certificate. When that dial fails or the
# upstream closes straight away, the proxy keeps running and the device silently falls back to the
# real cloud, or loops on registration. KeepAlive cannot see that, so this watchdog reads the log
# and restarts the job when the failure rate is non-zero over a fresh window.
#
#   wyze_broker_watch.sh [interval]
set -u
INTERVAL=${1:-60}
LOG=/tmp/ota/broker.log
JOB=system/com.jeffreyemanuel.wyze-broker

while :; do
  sleep "$INTERVAL"
  [ -r "$LOG" ] || continue
  before=$(wc -c < "$LOG" 2>/dev/null || echo 0)
  sleep 10
  after=$(wc -c < "$LOG" 2>/dev/null || echo 0)
  [ "$after" -ge "$before" ] || continue
  # only the bytes appended in the last 10 s matter
  recent=$(tail -c $((after - before + 1)) "$LOG" 2>/dev/null \
    | grep -cE "upstream fail|pipe S EOF|inject (delta|cmd) gave up" || true)
  if [ "${recent:-0}" -gt 3 ]; then
    echo "$(date +%H:%M:%S) $recent upstream failures in 10 s -> kickstart" >>/tmp/ota/broker-watch.log
    launchctl kickstart -k "$JOB" >>/tmp/ota/broker-watch.log 2>&1
    sleep 15
  fi
done
