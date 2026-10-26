#!/bin/sh
# End-to-end: capture a live owner-authorized camera into a deployment, then run the advertised
# pipeline over it (motion watch -> orient). One command, real hardware, no fixtures.
#
#   ./e2e_capture.sh <camera-ip> [seconds]
#
# The cfg comes from /Users/jemanuel/fss-exploit/cfg/<ip>.json (uid/enr/mac); bind_ip is rewritten
# to this host because the stored value goes stale when the interface address changes.
set -eu
IP=${1:?camera ip}
SECS=${2:-30}
ROOT=${ROOT:-/tmp/fss-e2e}
CFG=/tmp/cfg-$(echo "$IP" | tr . _).json
BIN=$(dirname "$0")/../../target/debug

python3 - "$IP" "$CFG" <<'PY'
import json, sys, subprocess
ip, out = sys.argv[1], sys.argv[2]
src = f"/Users/jemanuel/fss-exploit/cfg/{ip}.json"
d = json.load(open(src))
d["bind_ip"] = subprocess.run(["ipconfig", "getifaddr", "en1"], capture_output=True, text=True).stdout.strip()
json.dump(d, open(out, "w"))
PY
chmod 600 "$CFG"

echo "== capture $IP for ${SECS}s"
"$BIN/fss-capture-tutk" --root "$ROOT" --cfg "$CFG" --secs "$SECS" --owner-authorized > /tmp/e2e-capture.json
cat /tmp/e2e-capture.json

IMP=$(python3 -c "import json;print(json.load(open('/tmp/e2e-capture.json')).get('import_id',''))" 2>/dev/null || true)
[ -n "$IMP" ] || { echo "no import id; capture produced nothing"; exit 1; }

echo "== motion watch"
"$BIN/fss-event" watch --root "$ROOT" --site e2e --import-id "$IMP" --interpretation ycbcr \
  --zone yard:0,0,640,360 --report-out /tmp/e2e-watch.json > /tmp/e2e-watch.log 2>&1 || true
tail -3 /tmp/e2e-watch.log

echo "== orient"
"$BIN/fss" session orient --root "$ROOT" --site e2e --json 2>&1 | head -30
