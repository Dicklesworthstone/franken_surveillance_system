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
CAM=${CAM:-192.168.4.24}

# One daemon restart carries every shape: the injector cycles OTA_SHAPES per iteration,
# so a single hardware wake covers all of them. Shape 0 is the exact captured cloud body.
SHAPES='[{"top":{},"params":{}},
 {"top":{"sub_mac":"MAC"},"params":{}},
 {"top":{},"params":{"sub_mac":"MAC","device_id":"MAC"}},
 {"top":{},"params":{"hardware_ver":"0.0.0.0","current_ver":"4.52.17.32"}},
 {"top":{"encrypt_type":1,"ver":"1"},"params":{}},
 {"top":{},"params":{"product_type":"camera","product_model":"HL_CAM4"}},
 {"top":{},"params":{"id":9462,"test_code":"Test Version"}}]'
MAC_U=80482C4BCF0B

set_env() {  # $1 top-level json, $2 params json
  sudo /opt/homebrew/bin/python3 - "$1" "$2" <<'PY'
import plistlib, sys
p = "/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist"
d = plistlib.load(open(p, "rb"))
e = d["EnvironmentVariables"]
e["OTA_ACTIONS"] = "upgrade"
e["OTA_ENC"] = "3"
e["OTA_ENR"] = "O7y73ZL+K47xvSPY"
e["CAP_PATH"] = "wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar"
e["CAM"] = "192.168.4.24"
e["MAC"] = "80482c4bcf0b"
e.pop("OTA_RAWHEX", None)
e.pop("OTA_EXTRA", None); e.pop("OTA_PARAMS_EXTRA", None)
e["OTA_SHAPES"] = sys.argv[1]
e["OTA_VIA_UPSTREAM"] = "1"
e.pop("NO_UPSTREAM", None)
plistlib.dump(d, open(p, "wb"))
PY
}

run() {
  local n=$1
  ping -c1 -W800 "$CAM" >/dev/null 2>&1 || { echo "device down"; return 1; }
  local mark
  mark=$(sudo wc -l < "$FORGE")
  set_env
  sudo launchctl bootout system/com.jeffreyemanuel.wyze-broker 2>/dev/null
  sleep 2
  sudo launchctl bootstrap system "$PLIST"
  echo "shapes armed (one restart, 20 iterations)"
  for _ in $(seq 1 40); do
    sleep 3
    if sudo tail -n +"$((mark + 1))" "$FORGE" | grep -q "4.52.17.33.tar"; then
      echo "FETCH"
      sudo tail -n +"$((mark + 1))" "$FORGE" | grep "4.52.17.33.tar"
      return 0
    fi
  done
  echo "no fetch"
  return 1
}

run 1 && exit 0
echo "no fetch on any shape"
