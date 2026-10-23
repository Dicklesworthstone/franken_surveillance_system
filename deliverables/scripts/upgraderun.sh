#!/bin/sh
# upgraderun.sh — wire-only Thingino installer for Wyze Cam v4 (HL_CAM4, T41NQ).
#
# Runs as root from `assis` after it downloaded and extracted our tar to /tmp.
# Carrier is a 16 MiB full-chip image written into the existing MTD partitions
# as absolute slices; the bootloader goes last. Backups are streamed to the
# operator before any write.
#
# Substituted by build_ota_tar.py --render: @HOST@ @PORT@ @IMG_PORT@ @IMAGE@ @SHA256@ @SENSOR@
# The capsule itself arrives over HTTPS through assis; the 16 MiB image is fetched by the
# static busybox over plain HTTP and verified by SHA-256 before any write.
set -e

HOST=@HOST@
PORT=@PORT@
IMG_PORT=@IMG_PORT@
IMG_URL="http://$HOST:$IMG_PORT/@IMAGE@"
IMG_SHA=@SHA256@
SENSOR="@SENSOR@"
CHIP=16777216
BB=/tmp/Upgrade/busybox

log() { echo "[fss-ota] $*"; }
die() { log "FATAL: $*"; exit 1; }

[ -x "$BB" ] || die "static busybox missing"
[ -r /proc/mtd ] || die "no /proc/mtd"

# ---- 1. geometry -----------------------------------------------------------
# Expect exactly the stock map, in the stock order. Anything else is refused.
expect="uboot boot system back cfg provisioning"
got=""
total=0
while read -r dev size erase name; do
    n=${name#\"}; n=${n%\"}
    got="$got $n"
    total=$((total + 0x$size))
done < /proc/mtd
[ "$(echo $got)" = "$expect" ] || die "unexpected mtd map:$got"
[ "$total" -eq "$CHIP" ] || die "mtd total $total != $CHIP"
log "geometry ok: $(echo $got)"

# ---- 2. backups to the operator, then verify -------------------------------
slot=0
while read -r dev size erase name; do
    n=${name#\"}; n=${n%\"}
    sz=$((0x$size))
    log "backup mtd$slot ($n, $sz bytes)"
    "$BB" dd if="/dev/mtdblock$slot" bs=4096 count=$((sz / 4096)) \
        | "$BB" nc "$HOST" $((PORT + 1 + slot)) || die "backup $n failed"
    slot=$((slot + 1))
done < /proc/mtd
log "backups streamed; continuing in 5 s"
sleep 5

# ---- 3. fetch + verify the image ------------------------------------------
"$BB" wget -q -O /tmp/thingino.bin "$IMG_URL" || die "download failed"
[ "$(wc -c < /tmp/thingino.bin)" -eq "$CHIP" ] || die "short image"
echo "$IMG_SHA  /tmp/thingino.bin" | "$BB" sha256sum -c - || die "digest mismatch"
sync

# ---- 4. write, highest partition first, bootloader last --------------------
off=0
plan=""
while read -r dev size erase name; do
    n=${name#\"}; n=${n%\"}
    plan="$off:$((0x$size)):$n $plan"   # prepend: highest partition ends up first
    off=$((off + 0x$size))
done < /proc/mtd

write_one() { # $1 = absolute offset, $2 = length, $3 = mtd index
    log "write $2 bytes at 0x$1 -> mtdblock$3"
    "$BB" dd if=/tmp/thingino.bin of="/dev/mtdblock$3" bs=4096 \
        skip=$(($1 / 4096)) count=$(($2 / 4096)) || die "write mtd$3 failed"
}

i=0
for spec in $plan; do
    o=${spec%%:*}; rest=${spec#*:}; l=${rest%%:*}
    idx=$((5 - i))
    write_one "$o" "$l" "$idx"
    i=$((i + 1))
done
sync
log "image written (sensor $SENSOR); rebooting"

# assis also reboots on our return, but do not rely on it.
"$BB" reboot -f || true
