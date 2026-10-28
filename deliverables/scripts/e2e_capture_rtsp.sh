#!/bin/sh
# End-to-end over RTSP: prove the provisioned account, capture one bounded session, import it,
# then run the advertised pipeline (motion watch -> orient) over the retained import.
#
#   ./e2e_capture_rtsp.sh <camera-ip> <rtsp-user> <rtsp-password> [pictures]
#
# Prerequisites: the third account is provisioned and the unit has rebooted
# (`tapo_post.py <ip> --rtsp-enable --rtsp-reset`), and `fss-capture-rtsp` /
# `fss-import-rtsp` / `fss-event` / `fss` are built. The account is proven first
# with an authenticated DESCRIBE; a 401 stops here instead of burning a capture.
#
# Both binaries are approval-gated: the script runs the pure plan, reads the
# returned approval, then repeats the exact arguments with it. Nothing is
# rewritten between the two runs.
set -eu
IP=${1:?camera ip}
USER=${2:?rtsp user}
PASS=${3:?rtsp password}
PICS=${4:-300}
WAIT=${WAIT:-5}
ROOT=${ROOT:-/tmp/fss-e2e-rtsp}
SITE=${SITE:-e2e}
BIN=${BIN:-$(cd "$(dirname "$0")/../../target/debug" && pwd)}
HERE=$(cd "$(dirname "$0")" && pwd)
SENSOR=tapo-c460
STREAM=stream1
GEN=1
INGRESS=1
SSRC=1
FRAME_TICKS=3600          # 25 pictures/s at the fixed 90000 Hz clock
digest() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }
ANCHOR=sha256:$(digest fss-e2e-rtsp-anchor)
RECEIVE_CLOCK=sha256:$(digest fss-e2e-rtsp-receive-clock)
TIMING=sha256:$(digest fss-e2e-rtsp-timing)
JOURNAL=sha256:$(digest fss-e2e-rtsp-journal)

[ -x "$BIN/fss-capture-rtsp" ] || { echo "missing $BIN/fss-capture-rtsp (cargo build -p fss-cli)"; exit 1; }

echo "== prove the account (presence + authenticated DESCRIBE)"
"$HERE/tapo_post.py" "$IP" --rtsp-verify --rtsp-user "$USER" --rtsp-pass "$PASS" --wait "$WAIT"

REALM=$("$HERE/tapo_post.py" "$IP" --rtsp-realm) || { echo "no Digest realm"; exit 1; }
echo "  realm: $REALM"

mkdir -p "$ROOT"
CRED=$ROOT/credential
umask 077
printf '%s\n%s\n' "$USER" "$PASS" > "$CRED"
chmod 600 "$CRED"

ARCHIVE=$ROOT/archive
PINS=$ROOT/pins
[ -e "$ARCHIVE" ] || mkdir -p "$ARCHIVE"
[ -e "$PINS" ] || mkdir -p "$PINS"

capture_args() {
  printf '%s\n' \
    --root "$ARCHIVE" --pins "$PINS" \
    --peer "$IP:554" --authority "$IP:554" \
    --presentation "/$STREAM" --control-root "/$STREAM" \
    --sensor-id "$SENSOR" --stream-id "$STREAM" --generation "$GEN" \
    --ingress "$INGRESS" --ssrc "$SSRC" \
    --anchor "$ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
    --timing-evidence "$TIMING" --journal-id "$JOURNAL" \
    --frame-duration-ticks "$FRAME_TICKS" --stop-after-pictures "$PICS" \
    --owner-authorized yes --plaintext yes --retain-originals yes \
    --credential-file "$CRED" --auth-realm "$REALM"
}

echo "== plan"
# shellcheck disable=SC2046
"$BIN/fss-capture-rtsp" $(capture_args) > "$ROOT/capture-plan.json"
APPROVAL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["approval"])' \
  "$ROOT/capture-plan.json")
echo "  approval: $APPROVAL"

echo "== capture $PICS pictures"
# shellcheck disable=SC2046
"$BIN/fss-capture-rtsp" $(capture_args) --approve "$APPROVAL" > "$ROOT/capture.jsonl"

echo "== import every durable window"
RECEIVE_NS=$(python3 -c 'import time;print(time.time_ns())')
IMPORTS=""
python3 - "$ROOT/capture.jsonl" > "$ROOT/windows.txt" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("kind") == "window_durable":
        print(rec["slot"], rec["root"])
PY
[ -s "$ROOT/windows.txt" ] || { echo "no durable window; capture produced nothing"; exit 1; }

while read -r SLOT WROOT; do
  import_args() {
    printf '%s\n' \
      --archive "$ARCHIVE" --root "$ROOT/deployment" --site "$SITE" --codec avc \
      --window-slot "$SLOT" --window-root "$WROOT" \
      --sensor-id "$SENSOR" --stream-id "$STREAM" --generation "$GEN" \
      --anchor "$ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
      --receive-time-ns "$RECEIVE_NS" \
      --owner-authorized yes --read-originals yes --retain-originals yes
  }
  # shellcheck disable=SC2046
  "$BIN/fss-import-rtsp" $(import_args) > "$ROOT/import-plan-$SLOT.json"
  IAPPROVAL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["approval_digest"])' \
    "$ROOT/import-plan-$SLOT.json")
  # shellcheck disable=SC2046
  "$BIN/fss-import-rtsp" $(import_args) --approve "$IAPPROVAL" > "$ROOT/import-$SLOT.json"
  ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["import_identity"])' \
    "$ROOT/import-$SLOT.json")
  echo "  imported $SLOT -> $ID"
  IMPORTS="$IMPORTS $ID"
done < "$ROOT/windows.txt"

echo "== motion watch"
for ID in $IMPORTS; do
  "$BIN/fss-event" watch --root "$ROOT/deployment" --site "$SITE" --import-id "$ID" \
    --interpretation ycbcr --zone yard:0,0,640,360 \
    --report-out "$ROOT/watch-$(echo "$ID" | cut -c8-19).json" \
    > "$ROOT/watch-$(echo "$ID" | cut -c8-19).log" 2>&1 || true
  tail -3 "$ROOT/watch-$(echo "$ID" | cut -c8-19).log"
done

echo "== orient"
"$BIN/fss" session orient --root "$ROOT/deployment" --json 2>&1 | head -30
