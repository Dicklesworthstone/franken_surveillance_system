#!/bin/bash
# Sweep the injected `upgrade` body shape against a live device connection.
#
# Each shape is a superset of the last: the cloud body carries fields ours lacks,
# and the handler may reject on any of them. One shape per daemon restart; a fetch
# of the staged capsule in the forge log is the only success signal.
#
#   ./wyze_ota_sweep.sh            # all shapes
#   ./wyze_ota_sweep.sh 3          # one shape by number
set -u
PLIST=/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist
FORGE=/tmp/ota/forge.log
CAP=wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar
CAM=192.168.4.23

# top-level extra | Params extra
SHAPES=(
  '{}|{}'
  '{"sub_mac":"80482C525905"}|{}'
  '{}|{"sub_mac":"80482C525905","device_id":"80482C525905"}'
  '{}|{"hardware_ver":"0.0.0.0","current_ver":"4.52.17.32"}'
  '{"encrypt_type":1,"ver":"1"}|{}'
  '{}|{"product_type":"camera","product_model":"HL_CAM4"}'
  '{}|{"id":9462,"test_code":"Test Version"}'
)

set_env() {  # $1 top-level json, $2 params json
  sudo /opt/homebrew/bin/python3 - "$1" "$2" <<'PY'
import plistlib, sys
p = "/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist"
d = plistlib.load(open(p, "rb"))
e = d["EnvironmentVariables"]
e["OTA_ACTIONS"] = "upgrade"
e["OTA_ENC"] = "3"
e["CAP_PATH"] = "wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar"
e.pop("OTA_RAWHEX", None)
top, par = sys.argv[1], sys.argv[2]
if top != "{}":
    e["OTA_EXTRA"] = top
else:
    e.pop("OTA_EXTRA", None)
if par != "{}":
    e["OTA_PARAMS_EXTRA"] = par
else:
    e.pop("OTA_PARAMS_EXTRA", None)
plistlib.dump(d, open(p, "wb"))
PY
}

run() {
  local n=$1 top=$2 par=$3
  ping -c1 -W800 "$CAM" >/dev/null 2>&1 || { echo "shape $n: device down"; return 1; }
  local mark
  mark=$(sudo wc -l < "$FORGE")
  set_env "$top" "$par"
  sudo launchctl kickstart -k system/com.jeffreyemanuel.wyze-broker
  echo "shape $n: top=$top params=$par"
  for _ in $(seq 1 40); do
    sleep 3
    if sudo tail -n +"$((mark + 1))" "$FORGE" | grep -q "4.52.17.33.tar"; then
      echo "shape $n: FETCH"
      sudo tail -n +"$((mark + 1))" "$FORGE" | grep "4.52.17.33.tar"
      return 0
    fi
  done
  echo "shape $n: no fetch"
  return 1
}

only=${1:-}
for i in "${!SHAPES[@]}"; do
  n=$((i + 1))
  [ -n "$only" ] && [ "$only" != "$n" ] && continue
  top=${SHAPES[$i]%%|*}
  par=${SHAPES[$i]#*|}
  run "$n" "$top" "$par" && { echo "stopping at shape $n"; exit 0; }
done
echo "all shapes exhausted"
