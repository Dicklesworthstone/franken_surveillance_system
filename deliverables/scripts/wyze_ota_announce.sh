#!/bin/bash
# Keep announcing the capsule to a wedged Wyze unit until it fetches.
#
# The import is two broker publishes in the app's own form (recovered from the MITM log):
# `start` the test-protocol process, then `upgrade` with model/url/version/md5/sub_mac. The
# camera executes both — when iCamera is alive. These units degrade to "accepts TCP, answers
# nothing", so a single announce is lost; this repeats on a slow loop and witnesses the first
# fetch in the access log.
#
#   wyze_ota_announce.sh <mac> <url> <version> <md5> [rounds] [sleep]
set -u
MAC=${1:?mac}; URL=${2:?url}; VER=${3:?version}; MD5=${4:?md5}
ROUNDS=${5:-240}; PAUSE=${6:-58}
HERE=$(cd "$(dirname "$0")" && pwd)
SUB=$(printf %s "$MAC" | tr -d ":" | tr "a-f" "A-F")
LOG=/tmp/ota/fwserve_access.jsonl
mark=$(grep -ac -- "$VER" "$LOG" 2>/dev/null); mark=${mark:-0}
for i in $(seq 1 "$ROUNDS"); do
  /opt/homebrew/bin/python3 "$HERE/wyze_cmd.py" send "$MAC" \
    "{\"Action\":\"start\",\"Guid\":\"$SUB-$((1000+i))\",\"Params\":{\"processname\":\"wyzeedgeai_cam_v4_test_protocol\"}}" >/dev/null 2>&1
  sleep 2
  /opt/homebrew/bin/python3 "$HERE/wyze_cmd.py" send "$MAC" \
    "{\"Action\":\"upgrade\",\"Params\":{\"model\":\"HL_CAM4\",\"url\":\"$URL\",\"firmware_ver\":\"$VER\",\"md5\":\"$MD5\",\"sub_mac\":\"$SUB\"},\"sub_mac\":\"$SUB\",\"Guid\":\"$SUB-$((2000+i))\"}" >/dev/null 2>&1
  now=$(grep -ac -- "$VER" "$LOG" 2>/dev/null); now=${now:-0}
  if [ "$now" -gt "$mark" ]; then echo "$(date +%H:%M:%S) FETCH seen ($mark -> $now)"; mark=$now; fi
  sleep "$PAUSE"
done
