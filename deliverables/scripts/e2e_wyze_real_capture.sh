#!/bin/bash
# End-to-end real-hardware capture from Wyze Cam v4 into FSS through the single-session RTSP bridge.
#
#   ./e2e_wyze_real_capture.sh <camera-ip> <upstream-cred-file> [pictures]
#
# Pipeline exercised (zero mocks, real live camera footage):
#   Wyze Cam v4 (:554 SmolRTSP, 1 conn/IP, in-band SPS/PPS)
#     -> wyze_rtsp_bridge.py (1 upstream conn, verbatim RTP, real observed sprop-parameter-sets,
#        SHA-256 Digest downstream, audio discarded per GOAL-009)
#     -> fss-capture-rtsp (plan -> approve -> live bounded capture, durable window custody)
#     -> fss-import-rtsp  (plan -> approve -> source-verified import into deployment)
#     -> fss-event watch  (pure-Rust H.264 decode + motion/coverage report over retained import)
#     -> fss session orient --json (SituationFrame + coverage + provenance inspection)
#   Plus negative control (RUN_GAP_TEST=1): drops the bridge mid-capture and asserts explicit
#   shortfall / EOF termination with zero silent continuity.
set -euo pipefail

CAM_IP="${1:?camera ip (e.g. 192.168.4.51)}"
UP_CRED="${2:?path to 0600 upstream credential file (user LF pass LF)}"
PICS="${3:-60}"
RUN_GAP_TEST="${RUN_GAP_TEST:-1}"
INCLUDE_CAPTURE_TIME_HINT="${INCLUDE_CAPTURE_TIME_HINT:-1}"
PUBLISH_EVENTS="${PUBLISH_EVENTS:-1}"
ZONE="${ZONE:-yard:0,0,640,360}"
CAPTURE_TIMEOUT_MS="${CAPTURE_TIMEOUT_MS:-60000}"
SENSOR="${SENSOR:-wyze-$(echo "$CAM_IP" | awk -F. '{print $4}')}"
STREAM="${STREAM:-stream1}"
SITE="${SITE:-home-lab}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-18554}"
ROOT="${ROOT:-/tmp/fss-e2e-wyze-${SENSOR}-$(date +%Y%m%dT%H%M%SZ)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${BIN:-}" ]; then
  REPO_ROOT="$(cd "$HERE/../.." && pwd)"
  if [ -x "$REPO_ROOT/target/rch-camera-bins/fss-capture-rtsp" ]; then
    BIN="$REPO_ROOT/target/rch-camera-bins"
  elif [ -x "$REPO_ROOT/target/debug/fss-capture-rtsp" ]; then
    BIN="$REPO_ROOT/target/debug"
  elif [ -x "${CARGO_TARGET_DIR:-/data/cargo-targets}/debug/fss-capture-rtsp" ]; then
    BIN="${CARGO_TARGET_DIR:-/data/cargo-targets}/debug"
  else
    BIN="$REPO_ROOT/target/debug"
  fi
fi
FSS_BIN="${FSS_BIN:-}"
if [ -z "$FSS_BIN" ]; then
  if [ -x "$BIN/fss" ]; then
    FSS_BIN="$BIN/fss"
  elif [ -x "${CARGO_TARGET_DIR:-/data/cargo-targets}/debug/fss" ]; then
    FSS_BIN="${CARGO_TARGET_DIR:-/data/cargo-targets}/debug/fss"
  else
    FSS_BIN="$BIN/fss"
  fi
fi

sha256_str() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  fi
}

for b in fss-capture-rtsp fss-import-rtsp fss-event; do
  [ -x "$BIN/$b" ] || { echo "FATAL: missing binary $BIN/$b"; exit 1; }
done
[ -x "$FSS_BIN" ] || { echo "FATAL: missing binary $FSS_BIN"; exit 1; }
[ -r "$UP_CRED" ] || { echo "FATAL: unreadable upstream cred file $UP_CRED"; exit 1; }

mkdir -p "$ROOT"
umask 077
DN_CRED="$ROOT/bridge.cred"
DN_PASS="$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
printf 'fssbridge\n%s\n' "$DN_PASS" > "$DN_CRED"
chmod 600 "$DN_CRED"
unset DN_PASS

STATUS_JSON="$ROOT/bridge_status.json"
BRIDGE_LOG="$ROOT/bridge.log"
BRIDGE_PID=""
cleanup() {
  if [ -n "$BRIDGE_PID" ] && kill -0 "$BRIDGE_PID" 2>/dev/null; then
    kill "$BRIDGE_PID" 2>/dev/null || true
    wait "$BRIDGE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "== 1. Start single-session Wyze RTSP bridge -> $CAM_IP:554/$STREAM (listen $LISTEN_HOST:$LISTEN_PORT) =="
python3 "$HERE/wyze_rtsp_bridge.py" \
  --upstream-host "$CAM_IP" --upstream-port 554 --upstream-path "/$STREAM" \
  --upstream-cred-file "$UP_CRED" \
  --listen-host "$LISTEN_HOST" --listen-port "$LISTEN_PORT" --listen-path "/$STREAM" \
  --downstream-cred-file "$DN_CRED" --downstream-realm fss-bridge \
  --status-file "$STATUS_JSON" > "$BRIDGE_LOG" 2>&1 &
BRIDGE_PID=$!

READY=0
for _ in $(seq 1 40); do
  if [ -s "$STATUS_JSON" ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("ready") else 1)' "$STATUS_JSON" 2>/dev/null; then
    READY=1
    break
  fi
  sleep 0.5
done
[ "$READY" = 1 ] || { echo "FATAL: bridge never observed real SPS/PPS from $CAM_IP"; cat "$BRIDGE_LOG"; exit 1; }
echo "  bridge ready:"
cat "$STATUS_JSON"

ANCHOR="sha256:$(sha256_str "fss-e2e-wyze-anchor-$SENSOR")"
RECEIVE_CLOCK="sha256:$(sha256_str "fss-e2e-wyze-clock-$SENSOR")"
TIMING="sha256:$(sha256_str "fss-e2e-wyze-timing-$SENSOR")"
JOURNAL="sha256:$(sha256_str "fss-e2e-wyze-journal-$SENSOR")"

ARCHIVE="$ROOT/archive-run1"
PINS="$ROOT/pins-run1"
build_capture_args() {
  CAPTURE_ARGS=(
    --root "$1" --pins "$2"
    --peer "$LISTEN_HOST:$LISTEN_PORT" --authority "$LISTEN_HOST:$LISTEN_PORT"
    --presentation "/$STREAM" --control-root "/$STREAM"
    --sensor-id "$SENSOR" --stream-id "$STREAM" --generation "$3"
    --ingress 1 --ssrc auto
    --anchor "$ANCHOR" --receive-clock "$RECEIVE_CLOCK"
    --timing-evidence "$TIMING" --journal-id "$JOURNAL"
    --frame-duration-ticks 4500 --source-duration-max-ticks 18000 --source-no-reorder yes
    --stop-after-pictures "$4"
    --owner-authorized yes --plaintext yes --retain-originals yes
    --credential-file "$DN_CRED" --auth-realm fss-bridge
    --timeout-ms "$CAPTURE_TIMEOUT_MS" --drain-timeout-ms 15000 --response-timeout-ms 15000 \
    --max-storage-pause-ms 30000
  )
}

echo "== 2. Pure plan + approved real capture ($PICS pictures) via fss-capture-rtsp =="
build_capture_args "$ARCHIVE" "$PINS" 1 "$PICS"
"$BIN/fss-capture-rtsp" "${CAPTURE_ARGS[@]}" > "$ROOT/capture-plan.json"
APPROVAL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["approval"])' "$ROOT/capture-plan.json")
echo "  approval: $APPROVAL"
T_BEFORE_NS=$(python3 -c 'import time; print(time.time_ns())')
"$BIN/fss-capture-rtsp" "${CAPTURE_ARGS[@]}" --approve "$APPROVAL" > "$ROOT/capture.jsonl"
T_AFTER_NS=$(python3 -c 'import time; print(time.time_ns())')

echo "== 3. Durable windows captured =="
python3 - "$ROOT/capture.jsonl" > "$ROOT/windows.txt" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("kind") == "window_durable":
        d = rec.get("detail", rec)
        dur_ticks = max(0, int(d.get("decode_end", 0)) - int(d.get("decode_start", 0)))
        print(d["slot"], d["root"], d.get("pictures", 0), dur_ticks)
PY
cat "$ROOT/windows.txt"
[ -s "$ROOT/windows.txt" ] || { echo "FATAL: no durable windows captured"; cat "$ROOT/capture.jsonl"; exit 1; }

echo "== 4. Source-preserving import via fss-import-rtsp =="
RECEIVE_NS=$(python3 -c 'import time; print(time.time_ns())')
IMPORTS=()
while read -r SLOT WROOT WPICS WTICKS; do
  IMPORT_ARGS=(
    --archive "$ARCHIVE" --root "$ROOT/deployment" --site "$SITE" --codec avc
    --window-slot "$SLOT" --window-root "$WROOT"
    --sensor-id "$SENSOR" --stream-id "$STREAM" --generation 1
    --anchor "$ANCHOR" --receive-clock "$RECEIVE_CLOCK"
    --receive-time-ns "$RECEIVE_NS"
    --owner-authorized yes --read-originals yes --retain-originals yes
  )
  if [ "$INCLUDE_CAPTURE_TIME_HINT" = 1 ]; then
    read -r CAP_START_NS CAP_UNC_NS < <(python3 - "$T_BEFORE_NS" "$T_AFTER_NS" "$RECEIVE_NS" "$WPICS" "$WTICKS" <<'PY'
import sys
t0, t1, recv_ns, pics, ticks = [int(x) for x in sys.argv[1:6]]
win_dur_ns = (ticks * 1_000_000_000 // 90000) if ticks > 0 else (pics * 4500 * 1_000_000_000 // 90000)
unc_ns = max(1_000_000_000, t1 - t0)
start_ns = min(t0, recv_ns - win_dur_ns - unc_ns - 1_000_000_000)
print(start_ns, unc_ns)
PY
)
    IMPORT_ARGS+=(--capture-start-ns "$CAP_START_NS" --capture-uncertainty-ns "$CAP_UNC_NS")
  fi
  "$BIN/fss-import-rtsp" "${IMPORT_ARGS[@]}" > "$ROOT/import-plan-$SLOT.json"
  IAPP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["approval_digest"])' "$ROOT/import-plan-$SLOT.json")
  "$BIN/fss-import-rtsp" "${IMPORT_ARGS[@]}" --approve "$IAPP" > "$ROOT/import-$SLOT.json"
  ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["import_identity"])' "$ROOT/import-$SLOT.json")
  CTIME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("capture_time_label",""))' "$ROOT/import-$SLOT.json")
  echo "  imported window slot=$SLOT root=$WROOT frames=$WPICS capture_time=$CTIME -> import_id=$ID"
  IMPORTS+=("$ID")
done < "$ROOT/windows.txt"

echo "== 5. Pure-Rust H.264 decode + sensor-health + sampled luma hashes + CoverageWitness =="
WATCH_FAILS=0
for ID in "${IMPORTS[@]}"; do
  TAG=$(echo "$ID" | cut -c8-19)
  WATCH_BASE=(
    "$BIN/fss-event" watch --root "$ROOT/deployment" --site "$SITE" --import-id "$ID"
    --interpretation ycbcr --pixel-threshold 24 --min-region-pixels 64
    --zone "$ZONE" --sensor-health conservative-v1
  )
  set +e
  "${WATCH_BASE[@]}" --report-out "$ROOT/watch-$TAG.json" > "$ROOT/watch-$TAG.log" 2>&1
  WRC=$?
  set -e
  if [ "$WRC" -eq 0 ] && [ -s "$ROOT/watch-$TAG.json" ]; then
    python3 - "$ROOT/watch-$TAG.json" "$ID" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sh = d.get("sensor_health") or {}
obs = sh.get("observations") or []
uniq = len({o.get("luma_digest") for o in obs if o.get("luma_digest")})
samples = []
if obs:
    for idx in sorted({0, len(obs) // 2, len(obs) - 1}):
        o = obs[idx]
        samples.append(f"seg={o.get('segment')} luma={str(o.get('luma_digest',''))[:23]}.. contrast={o.get('contrast_span')} rep={o.get('repeated_frames')}")
print(
    f"  watch {sys.argv[2]}: rc=0 frames_decoded={d.get('frames_decoded',0)} "
    f"dims={d.get('width')}x{d.get('height')} health={sh.get('status')} "
    f"unique_luma={uniq} candidates={d.get('candidate_count',0)}"
)
for s in samples:
    print(f"    sample_frame_hash: {s}")
PY
    COV_APP=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d.get("coverage") or {}).get("approval_digest",""))' "$ROOT/watch-$TAG.json")
    if [ -n "$COV_APP" ]; then
      "${WATCH_BASE[@]}" --retain-coverage "$COV_APP" \
        --report-out "$ROOT/watch-$TAG-retained.json" > "$ROOT/watch-$TAG-retain.log" 2>&1
      COV_SUMMARY=$(python3 -c 'import json,sys; c=(json.load(open(sys.argv[1])).get("coverage") or {}); print("status=%s witnesses=%s absence_certified=%s" % (c.get("coverage_status"), c.get("witness_count", 0), c.get("absence_certified", False)))' "$ROOT/watch-$TAG-retained.json")
      echo "    coverage retained: $COV_SUMMARY"
    fi
    if [ "$PUBLISH_EVENTS" = 1 ]; then
      PROP_DIGEST=$(python3 -c 'import json,sys; cs=json.load(open(sys.argv[1])).get("candidates") or []; print(cs[0].get("proposal_digest","") if cs else "")' "$ROOT/watch-$TAG.json")
      if [ -n "$PROP_DIGEST" ]; then
        "${WATCH_BASE[@]}" --approve "$PROP_DIGEST" \
          --report-out "$ROOT/watch-$TAG-published.json" > "$ROOT/watch-$TAG-publish.log" 2>&1
        EVID=$(python3 -c 'import json,sys; cs=json.load(open(sys.argv[1])).get("candidates") or []; print(cs[0].get("event_id","") if cs else "")' "$ROOT/watch-$TAG-published.json")
        echo "    visible_event published: event_id=$EVID proposal=$PROP_DIGEST"
      fi
    fi
  else
    echo "  watch $ID (rc=$WRC):"
    tail -n 10 "$ROOT/watch-$TAG.log"
    WATCH_FAILS=$((WATCH_FAILS + 1))
  fi
done
echo "  watch_failures=$WATCH_FAILS"
[ "$WATCH_FAILS" -eq 0 ] || { echo "FATAL: $WATCH_FAILS fss-event watch invocation(s) failed"; exit 1; }

echo "== 6. Orient SituationFrame & CoverageWitness =="
"$FSS_BIN" session orient --root "$ROOT/deployment" --json > "$ROOT/orient.json"
python3 - "$ROOT/orient.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sf = (d.get("payload") or {}).get("situationFrame") or {}
anchor = d.get("outputAnchor") or (d.get("payload") or {}).get("anchor") or d.get("inputAnchor") or {}
cells = {c.get("cellId"): c.get("value") for c in (sf.get("knowledgeCells") or []) if isinstance(c, dict)}
print(f"  frameId={sf.get('frameId')} capsuleSequence={anchor.get('capsuleSequence')} epistemicState={d.get('epistemicState')} coverage={(sf.get('coverage') or {}).get('status')}")
for cid in ("claim:deployment:ledger-head", "claim:deployment:events", "claim:coverage:site"):
    if cid in cells:
        print(f"  {cid}: {cells[cid]}")
PY
echo "  bridge telemetry (video-only GOAL-009 audit):"
cat "$STATUS_JSON"

if [ "$RUN_GAP_TEST" = 1 ]; then
  echo "== 7. Negative test: drop upstream bridge mid-capture -> assert explicit shortfall (NO silent continuity) =="
  GAP_ARCH="$ROOT/archive-gap"
  GAP_PINS="$ROOT/pins-gap"
  build_capture_args "$GAP_ARCH" "$GAP_PINS" 2 400
  "$BIN/fss-capture-rtsp" "${CAPTURE_ARGS[@]}" > "$ROOT/gap-plan.json"
  GAPP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["approval"])' "$ROOT/gap-plan.json")
  set +e
  "$BIN/fss-capture-rtsp" "${CAPTURE_ARGS[@]}" --approve "$GAPP" > "$ROOT/gap-capture.jsonl" 2> "$ROOT/gap-capture.err" &
  CAP_PID=$!
  for _ in $(seq 1 20); do
    if [ -s "$STATUS_JSON" ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("active_clients", 0) >= 1 else 1)' "$STATUS_JSON" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  sleep 1
  echo "  simulating mid-stream camera disconnect (stopping bridge pid=$BRIDGE_PID)"
  kill "$BRIDGE_PID" 2>/dev/null || true
  wait "$BRIDGE_PID" 2>/dev/null || true
  BRIDGE_PID=""
  wait "$CAP_PID"
  GAP_RC=$?
  set -e
  echo "  gap-capture exit code=$GAP_RC (expected non-zero shortfall/interruption, NOT silent success)"
  python3 - "$ROOT/gap-capture.jsonl" <<'PY'
import json, sys
term = None
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("kind") == "terminal":
        term = rec.get("detail", rec)
if term:
    rt = term.get("runtime") or {}
    print(
        f"  gap_detection_log: error_id={term.get('error_id')} complete={term.get('complete')} "
        f"peer_eof={term.get('peer_eof')} capture_continuity={term.get('capture_continuity')} "
        f"collected={term.get('collected_pictures')}/{term.get('requested_pictures')} "
        f"custody_state={rt.get('custody_state')}"
    )
PY
  cat "$ROOT/gap-capture.err"
  [ "$GAP_RC" -ne 0 ] || { echo "FATAL: gap capture exited 0 despite mid-stream drop!"; exit 1; }
fi

echo "== E2E REAL WYZE CAPTURE COMPLETE (artifacts in $ROOT) =="
