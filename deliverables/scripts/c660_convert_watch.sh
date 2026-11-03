#!/bin/bash
# Root-conversion hook for the C660: the moment the bind shell answers, run the post-shell chain.
#
# The sweep (c660_sweep_watch.sh) finds the stack address and stops on SHELL; it does not convert.
# This watcher is armed independently and is inert until :4444 answers, so it costs the sweep
# nothing and needs no edit when the sweep's bookkeeping changes. One shot per boot: the state file
# is written before the chain so a crash cannot run it twice.
#
#   c660_convert_watch.sh            # wait, convert once, exit
#   FORCE=1 c660_convert_watch.sh    # ignore a previous run (a fresh boot)
#
# Exit: 0 chain ran, 3 already ran, 4 the unit never answered (with WATCH_DEADLINE).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MAC="${MAC:-50:3d:d1:2f:49:b9}"
LOG="${LOG:-/tmp/c660_convert.log}"
STATE="${STATE:-/tmp/c660_convert.state}"
POLL="${POLL:-10}"
SHELL_PORT="${SHELL_PORT:-4444}"
WATCH_DEADLINE="${WATCH_DEADLINE:-0}"        # minutes; 0 = forever
ARP_CMD="${ARP_CMD:-sudo -n /usr/sbin/arp -an}"
PING="${PING:-ping}"
POSTSHELL="${POSTSHELL:-$HERE/c660_postshell.sh}"

log() {
  local line
  line="$(date '+%Y-%m-%d %H:%M:%S') $*"
  printf '%s\n' "$line" >> "$LOG"
  [ -t 1 ] && printf '%s\n' "$line"
}

# One canonical form, identical to the sweep's: lowercase hex, every octet zero-padded, separators
# stripped. arp prints octets without leading zeros, so a raw or arithmetically-collapsed compare
# both lose information (`d1` and `0b` both become 0) and can match a foreign unit.
norm_mac() {
  local f out=
  for f in $(echo "$1" | tr 'A-F' 'a-f' | tr ':-.' '   '); do
    out="$out$(printf '%2s' "$f" | tr ' ' 0)"
  done
  echo "$out"
}
resolve_ip() {
  $ARP_CMD 2>/dev/null | awk '/\(incomplete\)/ { next }{ gsub(/[()]/, "", $2); print $2, $4 }' \
    | while read -r ip mac; do
        [ -n "$ip" ] || continue
        [ "$(norm_mac "$mac")" = "$(norm_mac "$MAC")" ] && { echo "$ip"; break; }
      done
}
# a shell implies presence, but ICMP is still required so a stale IP held by another box cannot
# hand us a foreign :4444
shell_up() {
  local ip
  ip="$(resolve_ip)"
  [ -n "$ip" ] || return 1
  "$PING" -c 1 -t 1 "$ip" >/dev/null 2>&1 || return 1
  nc -z -G 2 "$ip" "$SHELL_PORT" >/dev/null 2>&1 || return 1
  printf '%s' "$ip"
}

if [ -r "$STATE" ] && [ "${FORCE:-0}" != 1 ]; then
  log "state: $(cat "$STATE") — already ran (FORCE=1 to override)"
  exit 3
fi

log "watching for a shell on $MAC"
deadline=0
if [ "$WATCH_DEADLINE" != 0 ]; then
  deadline=$(( $(date +%s) + $(awk -v m="$WATCH_DEADLINE" 'BEGIN{printf "%d", m*60}') ))
fi
while :; do
  if ip="$(shell_up)"; then
    [ -n "$ip" ] && break
  fi
  if [ "$deadline" != 0 ] && [ "$(date +%s)" -ge "$deadline" ]; then
    log "no shell after ${WATCH_DEADLINE} min — not converting"
    exit 4
  fi
  sleep "$POLL"
done

log "SHELL on $ip:$SHELL_PORT — running the post-shell chain"
echo "converting $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
"$POSTSHELL" "$ip"
rc=$?
log "chain exit $rc (artifacts /tmp/pane1/$ip)"
[ "$rc" = 0 ] && echo "done $ip $(date '+%Y-%m-%d %H:%M:%S')" > "$STATE"
exit "$rc"
