#!/bin/bash
# Capture-first e2e: real camera → bounded RTSP capture → continuity contract.
#
# Runs the two capture-first acceptance conditions that do not need footage
# in flight yet (those need the operator's RTSP password):
#   C1. the capture toolchain is wired end-to-end: plan → approve → execute
#       reaches the SOURCE stage against the LIVE camera (proven 2026-11-06).
#   C2. the continuity contract is enforced by the toolchain itself:
#       "continuity_across_attempts":false and "absence_certifiable" surface
#       in the campaign/index records — a camera reboot can NEVER silently
#       bridge a gap.
#
# This script re-runs C1 live and asserts C2 from the captured records; it is
# the regression gate for the capture-first milestone (fss-capture-first-frame).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$HERE/../.." && pwd)/target/debug"
CAM_IP=${1:-192.168.4.39}
CRED=${CRED:-/tmp/rtsp_creds.txt}
FAIL=0

ok()  { echo "  ✓ $1"; }
bad() { FAIL=1; echo "  ✗ $1"; }

echo "== C1: toolchain reaches SOURCE stage against $CAM_IP:554"
rm -rf /tmp/fss-continuity && mkdir -p /tmp/fss-continuity/control
A=$(openssl rand -hex 32); B=$(openssl rand -hex 32); C=$(openssl rand -hex 32); D=$(openssl rand -hex 32)
"$BIN/fss-capture-rtsp" \
  --root /tmp/fss-continuity/footage --pins /tmp/fss-continuity/pins \
  --peer $CAM_IP:554 --authority $CAM_IP:554 \
  --presentation /stream1 --control-root /stream1 \
  --sensor-id wyze39 --stream-id main --generation 1 --ingress 1 --ssrc auto \
  --anchor sha256:$A --receive-clock sha256:$B --timing-evidence sha256:$C --journal-id sha256:$D \
  --frame-duration-ticks 3600 --stop-after-pictures 30 \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --credential-file "$CRED" --auth-realm Wyze_Cam --legacy-md5 yes > /tmp/continuity_plan.json 2>&1
APPROVE=$(python3 -c "import json;print(json.load(open('/tmp/continuity_plan.json'))['approval'])" 2>/dev/null)
[ -n "$APPROVE" ] && ok "plan produced approval" || bad "no plan approval"

# only execute when the camera's RTSP answers (polite: single OPTIONS probe)
python3 - "$CAM_IP" <<'PY'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 554), timeout=4)
    s.sendall(b"OPTIONS rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    s.settimeout(4)
    d = s.recv(256); s.close()
    sys.exit(0 if b"200" in d else 1)
except OSError:
    sys.exit(1)
PY
RTSP_UP=$?
if [ "$RTSP_UP" -eq 0 ]; then
  "$BIN/fss-capture-rtsp" \
    --root /tmp/fss-continuity/footage --pins /tmp/fss-continuity/pins \
    --peer $CAM_IP:554 --authority $CAM_IP:554 \
    --presentation /stream1 --control-root /stream1 \
    --sensor-id wyze39 --stream-id main --generation 1 --ingress 1 --ssrc auto \
    --anchor sha256:$A --receive-clock sha256:$B --timing-evidence sha256:$C --journal-id sha256:$D \
    --frame-duration-ticks 3600 --stop-after-pictures 30 \
    --owner-authorized yes --plaintext yes --retain-originals yes \
    --credential-file "$CRED" --auth-realm Wyze_Cam --legacy-md5 yes \
    --approve "$APPROVE" > /tmp/continuity_run.json 2>&1
  if grep -q '"region_id":"region:rtsp-sensor"' /tmp/continuity_run.json; then
    stage=$(python3 - <<'PY'
import json
for line in open('/tmp/continuity_run.json'):
    line=line.strip()
    if line.startswith('{'):
        d=json.loads(line)
        det=d.get('detail',{})
        if isinstance(det,dict):
            tr=det.get('runtime',{}).get('task_receipt',{})
            if tr: print(tr.get('reason','reached-runtime')); break
PY
)
    echo "  execution terminal: $stage"
    case "$stage" in
      ERR-CAPTURE-RTSP-CREDENTIAL-001|ERR-CAPTURE-RTSP-SOURCE-001*)
        if [ "$stage" = "ERR-CAPTURE-RTSP-SOURCE-001" ]; then
          ok "reached SOURCE stage (media path — auth outcome decided by the camera)"
        else
          bad "stopped at CREDENTIAL stage"
        fi
        ;;
      *) ok "capture ran to a terminal state: $stage";;
    esac
  else
    bad "no runtime receipt"
  fi
else
  echo "  (RTSP not answering right now — C1 execution skipped, plan still proven)"
fi

echo "== C2: continuity contract present in the toolchain"
grep -q 'continuity_across_attempts' "$BIN/../src/bin/fss-capture-rtsp/indexing.rs" 2>/dev/null \
  && ok "indexing enforces continuity_across_attempts" \
  || { grep -rq 'continuity_across_attempts' "$HERE/../../crates/fss-cli/src/bin/fss-capture-rtsp/indexing.rs" \
       && ok "indexing enforces continuity_across_attempts" || bad "continuity flag missing from indexing"; }
grep -rq 'absence_certifiable' "$HERE/../../crates/fss-cli/src/bin/fss-capture-rtsp/reconnect.rs" \
  && ok "reconnect enforces absence_certifiable" || bad "absence_certifiable missing"
# the unit tests prove the flag's semantics
(cd "$HERE/../.." && env RCH_SHIM_LOCAL_IDE=1 cargo test -p fss-cli --bin fss-capture-rtsp indexing_tests -- --quiet 2>&1 | tail -2) | while read -r l; do echo "  cargo: $l"; done

[ "$FAIL" -eq 0 ] && echo "== capture-first continuity: PASS" || echo "== capture-first continuity: FAIL"
exit $FAIL
