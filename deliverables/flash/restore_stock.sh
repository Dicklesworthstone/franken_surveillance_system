#!/bin/sh
# restore_stock.sh — verified full-chip stock rollback installer for Wyze Cam v4 (HL_CAM4, T41NQ).
#
# Delivered over the same OTA capsule path (`Upgrade/upgraderun.sh` via `assis`) or invoked from
# a root shell after a Thingino flash. Enforces:
#   1. Exact /proc/mtd geometry check (accepts ONLY the pinned 16 MiB stock or Thingino maps).
#   2. Full-image size + SHA-256 verification BEFORE writing a single byte.
#   3. High-to-low partition write order (bootloader mtd0 written LAST).
#   4. Per-partition read-back SHA-256 verification before reboot (dm-verity coherence preserved).
#
# Rendered by deliverables/flash/safety_net.py build-restore-capsule:
#   @HOST@ @IMG_PORT@ @IMAGE@ @SHA256@ @MTD0_SHA@ @MTD1_SHA@ @MTD2_SHA@ @MTD3_SHA@ @MTD4_SHA@ @MTD5_SHA@
set -e

HOST=@HOST@
IMG_PORT=@IMG_PORT@
IMG_URL="http://$HOST:$IMG_PORT/@IMAGE@"
IMG_SHA=@SHA256@
BEACON_HOST=@BEACON_HOST@
BEACON_PORT=@BEACON_PORT@
CHIP=16777216
BB=/tmp/Upgrade/busybox
TMP_IMG=/tmp/stock-restore.bin
MTD_PROC=/proc/mtd
MTDBLK_PREFIX=/dev/mtdblock

MTD0_SHA=@MTD0_SHA@
MTD1_SHA=@MTD1_SHA@
MTD2_SHA=@MTD2_SHA@
MTD3_SHA=@MTD3_SHA@
MTD4_SHA=@MTD4_SHA@
MTD5_SHA=@MTD5_SHA@

beacon() {
    "$BB" wget -q -O /dev/null \
        "http://$BEACON_HOST:$BEACON_PORT/fss-ran?stage=restore-$1&uid=$("$BB" id -u 2>/dev/null)" \
        2>/dev/null || true
}

log() { echo "[fss-restore] $*"; }
die() { log "FATAL: $*"; beacon "fail:$1"; exit 1; }

beacon start
[ -x "$BB" ] || die "static-busybox-missing"
[ -r "$MTD_PROC" ] || die "no-proc-mtd"

# ---- 1. strict geometry validation (0 bytes written on mismatch) -----------
# Stock map:    uboot(512k) boot(2560k) system(5888k,dm-verity) back(5888k) cfg(1024k) provisioning(512k)
# Thingino map: boot(320k)  env(64k)    backup(64k)             kernel(1600k) rootfs(*) data(*) [optional all(16384k)]
got_names=""
got_sizes=""
total=0
count=0
while read -r dev size erase name; do
    case "$dev" in dev:*) continue ;; esac
    [ -n "$dev" ] || continue
    devnum=${dev#mtd}; devnum=${devnum%:}
    case "$devnum" in ''|*[!0-9]*) die "bad-mtd-dev-$dev" ;; esac
    n=${name#\"}; n=${n%\"}
    [ "$n" = "all" ] && continue
    sz=$((0x$size))
    [ $((sz % 4096)) -eq 0 ] || die "unaligned-mtd-$n"
    got_names="${got_names:+$got_names }$n"
    got_sizes="${got_sizes:+$got_sizes }$sz"
    total=$((total + sz))
    count=$((count + 1))
done < "$MTD_PROC"

stock_names="uboot boot system back cfg provisioning"
stock_sizes="524288 2621440 6029312 6029312 1048576 524288"
thingino_names="boot env backup kernel rootfs data"

layout=""
if [ "$got_names" = "$stock_names" ] && [ "$got_sizes" = "$stock_sizes" ] && [ "$total" -eq "$CHIP" ]; then
    layout="stock"
elif [ "$got_names" = "$thingino_names" ] && [ "$count" -eq 6 ] && [ "$total" -eq "$CHIP" ]; then
    layout="thingino"
else
    die "unexpected-mtd-map"
fi
beacon "geometry-$layout-ok"
log "geometry ok ($layout): $got_names ($total bytes)"

# ---- 2. fetch + full-image SHA-256 verification BEFORE any write -----------
beacon image-fetch
"$BB" wget -q -O "$TMP_IMG" "$IMG_URL" || die "download-failed"
img_len=$("$BB" wc -c < "$TMP_IMG")
[ "$img_len" -eq "$CHIP" ] || die "short-image-$img_len"
echo "$IMG_SHA  $TMP_IMG" | "$BB" sha256sum -c - || die "image-sha256-mismatch"
beacon image-verified
sync

# ---- 3. write high-to-low (bootloader written LAST; use actual kernel mtdN) ----
# Use the actual kernel device number parsed from /proc/mtd (`devnum`) so an
# aggregate `"all"` entry at mtd0 never shifts partition writes onto the wrong
# /dev/mtdblockN device. Keep logical slot index (`slot`) separately for stock
# per-partition SHA-256 lookup.
off=0
plan=""
slot=0
while read -r dev size erase name; do
    case "$dev" in dev:*) continue ;; esac
    [ -n "$dev" ] || continue
    devnum=${dev#mtd}; devnum=${devnum%:}
    case "$devnum" in ''|*[!0-9]*) die "bad-mtd-dev-$dev" ;; esac
    n=${name#\"}; n=${n%\"}
    [ "$n" = "all" ] && continue
    sz=$((0x$size))
    plan="$devnum:$slot:$off:$sz:$n $plan"
    off=$((off + sz))
    slot=$((slot + 1))
done < "$MTD_PROC"

expected_stock_sha() {
    case "$1" in
        0) echo "$MTD0_SHA" ;;
        1) echo "$MTD1_SHA" ;;
        2) echo "$MTD2_SHA" ;;
        3) echo "$MTD3_SHA" ;;
        4) echo "$MTD4_SHA" ;;
        5) echo "$MTD5_SHA" ;;
        *) echo "" ;;
    esac
}

for spec in $plan; do
    pidx=${spec%%:*}; rest=${spec#*:}
    pslot=${rest%%:*}; rest=${rest#*:}
    poff=${rest%%:*}; rest=${rest#*:}
    psz=${rest%%:*}; pname=${rest#*:}
    log "write mtd$pidx (slot=$pslot $pname, $psz bytes @ $poff)"
    "$BB" dd if="$TMP_IMG" of="${MTDBLK_PREFIX}${pidx}" bs=4096 \
        skip=$((poff / 4096)) count=$((psz / 4096)) || die "write-mtd$pidx-failed"
    beacon "write-mtd$pidx"

    # Per-partition read-back hash check immediately after write (stock map has pinned per-partition SHAs)
    if [ "$layout" = "stock" ]; then
        want_sha="$(expected_stock_sha "$pslot")"
        got_sha=$("$BB" dd if="${MTDBLK_PREFIX}${pidx}" bs=4096 count=$((psz / 4096)) 2>/dev/null \
            | "$BB" sha256sum | "$BB" awk '{print $1}')
        [ "$got_sha" = "$want_sha" ] || die "verify-mtd$pidx-mismatch"
        beacon "verify-mtd$pidx-ok"
        log "verified mtd$pidx ($pname) sha256=$got_sha"
    fi
done

if [ "$layout" = "thingino" ]; then
    # Concatenate all 6 written slices in ascending order using actual kernel mtdN and verify full-chip SHA-256 == stock image
    full_sha=$(
        while read -r dev size erase name; do
            case "$dev" in dev:*) continue ;; esac
            [ -n "$dev" ] || continue
            devnum=${dev#mtd}; devnum=${devnum%:}
            n=${name#\"}; n=${n%\"}
            [ "$n" = "all" ] && continue
            sz=$((0x$size))
            "$BB" dd if="${MTDBLK_PREFIX}${devnum}" bs=4096 count=$((sz / 4096)) 2>/dev/null
        done < "$MTD_PROC" | "$BB" sha256sum | "$BB" awk '{print $1}'
    )
    [ "$full_sha" = "$IMG_SHA" ] || die "verify-fullchip-mismatch"
    beacon "verify-fullchip-ok"
    log "verified full-chip sha256=$full_sha"
fi

sync
log "stock restore complete and hash-verified; rebooting"
beacon restored
"$BB" reboot || true
