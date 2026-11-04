#!/bin/bash
# launchd entrypoint for the Wyze LAN harness.
#
# It used to own the listeners itself; that duplicated wyze_mitm_up.sh and the two drifted (this
# script kept a hardcoded camera IP and en1, the other grew the port/alias/cert rebuild). It is now
# a thin wrapper: normalise the environment, mirror the versioned process dirs the responder
# advertises, then hand over to the one bring-up script in foreground mode so launchd supervises
# the MQTT proxy.
#
#   CAM=192.168.4.51 MAC=80482c4bcf0b ./wyze_ota_arm.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CAP_DIR="${CAP_DIR:-/tmp/fwserve}"

# The handler advertises PROC_VER and builds the download path from it, so the mirrored bytes must
# exist under that version too or every download 404s (81 of them, once).
for pair in "wyzeedgeai_cam_v4_test_protocol:14.9.50039.r" "kvsWebrtcClientMaster_t41:2.1.2.573"; do
  name=${pair%%:*}; src="$CAP_DIR/$name/${pair##*:}"
  dst="$CAP_DIR/$name/${PROC_VER:-14.9.50040.r}"
  [ -d "$src" ] && [ "$src" != "$dst" ] || continue
  mkdir -p "$dst"
  # an empty source dir makes the glob a literal path and cp fails noisily on every boot
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    [ -e "$dst/$(basename "$f")" ] || cp "$f" "$dst/"
  done
done

export CAM_MAC="${CAM_MAC:-${MAC:-80:48:2c:4b:cf:0b}}"
export OTA_ACTIONS="${OTA_ACTIONS:-start,upgrade,cmd}"
export PROC_NAME="${PROC_NAME:-wyzeedgeai_cam_v4_test_protocol}"
export CAP_DIR CAP_PATH="${CAP_PATH:-wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar}"
export FOREGROUND=1
echo "arm: cam=$CAM_MAC path=$CAP_PATH md5=${OTA_MD5:-<from file>}" 2>/dev/null \
  | sudo -n tee -a /tmp/ota/arm.log >/dev/null || true
exec "$HERE/wyze_mitm_up.sh"

# NOTE: everything below this line used to be the forge bring-up, and was dead code — `exec`
# replaces the shell, so it never ran. The forge on :443 (with --iot-cert and --iot-cert-dir) is
# now launched by wyze_mitm_up.sh itself, which also kills any stale listener first (including
# copies launched from deleted worktrees, whose old code serves a bare rootCA and breaks
# broker-leaf validation).
