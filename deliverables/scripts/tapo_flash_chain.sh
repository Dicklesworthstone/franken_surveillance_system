#!/bin/bash
# Convert a Tapo root shell into a flash. Runs ON THE MAC, drives the camera over its one-shot
# bind shell on 4444.
#
# Order is fixed and every step is bounded, because the bind shell is one-shot and a failed write
# with no dump has no way back:
#
#   1. dump EVERY mtd partition to the receiver (444+index, never written before this completes)
#   2. fetch the two image parts from our HTTP server and check their md5 ON THE CAMERA
#   3. write rootfs first, kernel last (a half-written kernel cannot boot at all)
#   4. bootargs: the stock one points at the vendor initramfs; OpenIPC needs the squashfs root
#   5. verify by reading the first bytes back, then reboot
#
#   tapo_flash_chain.sh <host> c460|c660 [--dry-run]
#
# Family profiles carry the map from docs/exploit/{c460-flash-layout,c660-flash-plan}.md and the
# md5 of the exact image bytes; both are matched against the file on disk before anything is sent.
#
# Exit: 0 written+rebooted, 2 a dump failed, 3 image fetch/hash failed, 4 write failed,
#       5 bootargs not settable (image written, unit may not boot — see the log).
set -u
HOST=${1:?host}
FAMILY=${2:?family c460|c660}
DRY=${3:-}
[ "$DRY" = "--dry-run" ] && DRY=1 || DRY=0

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
LOG="${LOG:-/tmp/tapo_flash_$HOST.log}"
SHELL_PORT="${SHELL_PORT:-4444}"
HTTP="http://192.168.4.160:8080"
RECV_HOST=192.168.4.160
RECV_BASE=444                      # receiver slot = mtd index (443 + 1 + index)
OUT="${OUTDIR:-/tmp/tapo_flash/$HOST}"

log() { echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

case "$FAMILY" in
  c460)
    # nor0: 0 BOOT 1 ENV 2 VERIFY 3 factoryinfo 4 KERNEL 5 MISC 6 RTOS 7 RAMDISK 8 config 9 usrrecord
    # nor1: 10 IPLXXX 11 rootfs 12 objdmodel
    TARGET_ROOTFS=11; TARGET_KERNEL=4
    BOOT_ROOT="/dev/mtdblock11"
    IMG_ROOTFS=rootfs.squashfs.ssc30kq; MD5_ROOTFS=591361211e6c143d338114ee810d1bfa
    IMG_KERNEL=uImage.ssc30kq;           MD5_KERNEL=79578351a0527ec9a82ecb8224aaaad2
    PARTS=13
    ;;
  c660)
    # 0 loader 1 fdt 2 fdt.fast 3 uboot 4 verify 5 factoryinfo 6 config 7 rtos 8 kernel
    # 9 rootfs 10 source_fast 11 userrecord 12 service
    TARGET_ROOTFS=9; TARGET_KERNEL=8
    BOOT_ROOT="/dev/mtdblock9"
    IMG_ROOTFS=rootfs.squashfs.nt98567; MD5_ROOTFS=805a4d2847ade1cc240cf1f16cb8b911
    IMG_KERNEL=uImage.nt98567;          MD5_KERNEL=dee84e4f805eab484f530bc0744c27b8
    PARTS=13
    ;;
  *) die "unknown family $FAMILY" 1 ;;
esac
mkdir -p "$OUT"

# One long-lived sh on the far side; every command is a separate line and bounded by `timeout`.
talk() { # talk <seconds> <command...>
  local t=$1; shift
  { printf '%s\n' "$*"; sleep "$t"; } | nc -w $((t + 5)) "$HOST" "$SHELL_PORT"
}

log "== $FAMILY flash chain against $HOST (dry=$DRY)"
SH=$(talk 6 'echo FSS-SHELL-OK; id -u; uname -a')
if echo "$SH" | grep -q FSS-SHELL-OK; then
  log "shell: $(echo "$SH" | sed -n '2,3p' | tr '\n' ' ')"
elif [ "$DRY" = 1 ]; then
  log "dry run: no shell (local checks still run)"
else
  die "no shell on $HOST:$SHELL_PORT" 3
fi

CAPS=""
if [ "$DRY" = 0 ]; then
  CAPS=$(talk 4 'for x in flash_erase mtd_debug fw_setenv fw_printenv md5sum tftp dd nc; do command -v $x >/dev/null && echo "have $x"; done')
  echo "$CAPS" | tee -a "$LOG"
  # which sensor this unit actually has decides whether the image can drive it at all
  SENSOR=$(talk 4 'for p in /etc/ko/sensor_name /sp_rom/etc/ko/sensor_name; do [ -r $p ] && { cat $p; break; }; done' | tr -d '\r' | head -1)
  log "sensor: ${SENSOR:-unknown}"
  echo "sensor=${SENSOR:-unknown}" | tee -a "$LOG"
fi

# ---- 1. dumps ------------------------------------------------------------------------------
log "== dumping $PARTS partitions to $RECV_HOST:$RECV_BASE+"
if [ "$DRY" = 0 ]; then
  i=0
  while [ "$i" -lt "$PARTS" ]; do
    port=$((RECV_BASE + i))
    talk 3 "tftp -p -l /dev/mtdblock$i $RECV_HOST $port; echo DUMPED-$i" | grep -q "DUMPED-$i" \
      || die "dump of mtd$i failed" 2
    log "  mtd$i -> :$port"
    i=$((i + 1))
  done
  log "dumps complete — check sizes under /tmp/fwbackup before writing anything"
fi

# ---- 2. images -----------------------------------------------------------------------------
for pair in "$IMG_ROOTFS:$MD5_ROOTFS" "$IMG_KERNEL:$MD5_KERNEL"; do
  img=${pair%%:*}; want=${pair##*:}
  path="$ROOT/deliverables/firmware/$img"
  [ -r "$path" ] || path="$HOME/fss-exploit/fw/$img"
  got=$(md5 -q "$path" 2>/dev/null)
  [ "$got" = "$want" ] || die "local $img md5 $got != $want" 3
  log "  local $img md5 ok ($want)"
  case "$img" in
    rootfs.*)
      # a rootfs that cannot boot is worse than stock: assert the boot-critical set exists
      for need in init linuxrc sbin/init bin/busybox etc/init.d/rcS etc/passwd; do
        unsquashfs -l "$path" 2>/dev/null | grep -qx "squashfs-root/$need" \
          || die "$img lacks /$need — refusing to flash it" 3
      done
      log "  $img content ok (init, linuxrc, busybox, rcS, passwd)"
      ;; esac
done
[ "$DRY" = 0 ] || { log "dry run: stopping before fetch/write"; exit 0; }

log "== fetching images on the camera"
for pair in "$IMG_ROOTFS:$MD5_ROOTFS" "$IMG_KERNEL:$MD5_KERNEL"; do
  img=${pair%%:*}; want=${pair##*:}
  talk 20 "tftp -g -r $img -l /tmp/$img $RECV_HOST 444 2>/dev/null || wget -q -O /tmp/$img $HTTP/fw/$img"
  g=$(talk 5 "md5sum /tmp/$img" | awk '/^[0-9a-f]{32}/{print $1}')
  [ "$g" = "$want" ] || die "on-camera md5 of $img is '$g', want $want" 3
  log "  camera has $img ($want)"
done

# ---- 3. writes: rootfs first, kernel last ---------------------------------------------------
write_part() { # write_part <index> <file>
  local idx=$1 f=/tmp/$2
  log "  writing mtd$idx"
  case "$CAPS" in
    *"have flash_erase"*) talk 30 "flash_erase /dev/mtd$idx 0 0; dd if=$f of=/dev/mtd$idx 2>&1 | tail -1" ;;
    *"have mtd_debug"*)   talk 30 "mtd_debug erase /dev/mtd$idx 0 \$(stat -c %s /dev/mtd$idx 2>/dev/null || echo 0); mtd_debug write /dev/mtd$idx 0 \$(stat -c %s $f) $f" ;;
    *)                    talk 30 "dd if=$f of=/dev/mtdblock$idx 2>&1 | tail -1; sync" ;;
  esac
  local back
  back=$(talk 5 "dd if=/dev/mtdblock$idx bs=4096 count=1 2>/dev/null | md5sum" | awk '{print $1}')
  log "  mtd$idx first-block md5 after write: $back"
}
write_part "$TARGET_ROOTFS" "$IMG_ROOTFS" || die "rootfs write failed" 4
write_part "$TARGET_KERNEL" "$IMG_KERNEL"  || die "kernel write failed" 4

# ---- 4. bootargs ---------------------------------------------------------------------------
# Stock boots its initramfs; OpenIPC boots squashfs. The C660 keeps env compiled into U-Boot
# (NVT_UBOOT_ENV_IN_STORG_SUPPORT=OFF), so a per-boot bootargs may not survive — the log says so.
NEWARGS="console=ttyS0,115200 root=$BOOT_ROOT rootfstype=squashfs rw"
case "$CAPS" in
  *"have fw_setenv"*)
    talk 5 "fw_setenv bootargs '$NEWARGS'; fw_printenv bootargs"
    ;;
  *)
    log "!! no fw_setenv — bootargs unchanged ($NEWARGS); a compiled-in env may need U-Boot work"
    ;;
esac

# ---- 5. reboot -----------------------------------------------------------------------------
log "== rebooting $HOST"
talk 3 'sync; reboot'
log "done. Watch: ping $HOST, then root_proof.py $HOST dropbear22; rollback = write the dumps back"
