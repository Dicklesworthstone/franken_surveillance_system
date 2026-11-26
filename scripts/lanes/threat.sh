#!/usr/bin/env bash
# QL-THREAT-001 — Reusable local qualification lane: threat & corroboration (`fss-x4a.29.9`).
#
# Exact scope (`architecture/release_qualification.json`, `docs/LOCAL_QUALIFICATION_WITH_DSR.md`):
#   1. calibration_and_alert_budget     — split conformal calibration, e-process Ville bounds, fusion schemas
#   2. independence_and_failure_domains — d-separation shared-failure-domain audit & common-cause clustering
#   3. hard_negative_and_miss_ledger    — calibration invalidation, detector cascade recovery, ablation/miss audit
#   4. sensor_health_and_tamper         — sticky optical tamper/occlusion detection & degraded coverage screening
#   5. multi_source_corroboration       — multi-camera, geometry, stream, and historical health corroboration CLI
#
# Never contacts external providers or networks (`CARGO_NET_OFFLINE=true`).
# Never upgrades a skipped, unavailable, or failed check into a pass.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE_ID="QL-THREAT-001"
LANE_NAME="threat"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/lanes/threat.sh [--list] [--receipt-dir DIR]
                               [--verify-receipt RECEIPT_JSON [--allow-static-only]]
                               [--only-static] [--dry-run-missing-prereq]
USAGE
}

MODE="run"
RECEIPT_DIR="${FSS_THREAT_RECEIPT_DIR:-}"
VERIFY_TARGET=""
ONLY_STATIC=0
ALLOW_STATIC_ONLY=0
SIMULATE_MISSING_PREREQ=0

while (($#)); do
  case "$1" in
    --list) MODE="list"; shift ;;
    --receipt-dir) RECEIPT_DIR="${2:?missing path after --receipt-dir}"; shift 2 ;;
    --verify-receipt) MODE="verify"; VERIFY_TARGET="${2:?missing path after --verify-receipt}"; shift 2 ;;
    --allow-static-only) ALLOW_STATIC_ONLY=1; shift ;;
    --only-static) ONLY_STATIC=1; shift ;;
    --dry-run-missing-prereq) SIMULATE_MISSING_PREREQ=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'QL-THREAT-001: unknown argument: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

declare -a STEP_IDS=(
  "thr-01-threat-schema-constitution"
  "thr-02-threat-registry-consistency"
  "thr-03-conformal-eprocess-and-fusion"
  "thr-04-shared-failure-domain-dsep"
  "thr-05-calibration-invalidation-and-cascade"
  "thr-06-sensor-tamper-and-health-coverage"
  "thr-07-corroboration-and-health-cli-e2e"
)

declare -a STEP_PILLARS=(
  "calibration_and_alert_budget"
  "calibration_and_alert_budget"
  "calibration_and_alert_budget"
  "independence_and_failure_domains"
  "hard_negative_and_miss_ledger"
  "sensor_health_and_tamper"
  "multi_source_corroboration"
)

if [[ "$MODE" == "list" ]]; then
  for i in "${!STEP_IDS[@]}"; do
    printf '%s\t%s\t%s\n' "$LANE_ID" "${STEP_PILLARS[$i]}" "${STEP_IDS[$i]}"
  done
  exit 0
fi

if [[ "$MODE" == "verify" ]]; then
  exec python3 - "$VERIFY_TARGET" "$ALLOW_STATIC_ONLY" <<'PY'
import hashlib
import json
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
allow_static_only = sys.argv[2] == "1"
if not receipt_path.is_file():
    print(f"[FAIL] QL-THREAT-001 verifier: receipt missing: {receipt_path}", file=sys.stderr)
    sys.exit(2)

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] QL-THREAT-001 verifier: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if receipt.get("schema") != "fss.release_qualification_receipt.v1":
    print(f"[FAIL] unexpected schema: {receipt.get('schema')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("laneId") != "QL-THREAT-001":
    print(f"[FAIL] unexpected laneId: {receipt.get('laneId')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("status") != "passed":
    print(f"[FAIL] non-passing receipt status: {receipt.get('status')}", file=sys.stderr)
    sys.exit(1)
if not isinstance(receipt.get("sourceCommit"), str) or not receipt["sourceCommit"].startswith("git:"):
    print(f"[FAIL] malformed sourceCommit: {receipt.get('sourceCommit')!r}", file=sys.stderr)
    sys.exit(2)
if not isinstance(receipt.get("cargoLockDigest"), str) or not receipt["cargoLockDigest"].startswith("sha256:"):
    print(f"[FAIL] malformed cargoLockDigest: {receipt.get('cargoLockDigest')!r}", file=sys.stderr)
    sys.exit(2)

commands = receipt.get("commands")
if not isinstance(commands, list) or not commands:
    print("[FAIL] empty command record set", file=sys.stderr)
    sys.exit(2)

run_dir = receipt_path.parent
run_dir_resolved = run_dir.resolve()
steps_jsonl = run_dir / "threat-steps.jsonl"
if steps_jsonl.is_symlink() or not steps_jsonl.is_file():
    print(f"[FAIL] missing or symlinked structured step log: {steps_jsonl}", file=sys.stderr)
    sys.exit(2)

SECRET_MARKERS = ("BEGIN PRIVATE KEY", "AKIA", "rtsp-pass-gen1", "password=", "Authorization: Bearer ")
FULL_STEP_IDS = [
    "thr-01-threat-schema-constitution",
    "thr-02-threat-registry-consistency",
    "thr-03-conformal-eprocess-and-fusion",
    "thr-04-shared-failure-domain-dsep",
    "thr-05-calibration-invalidation-and-cascade",
    "thr-06-sensor-tamper-and-health-coverage",
    "thr-07-corroboration-and-health-cli-e2e",
]
STATIC_STEP_IDS = FULL_STEP_IDS[:2]
REQUIRED_FULL_PILLARS = {
    "calibration_and_alert_budget",
    "independence_and_failure_domains",
    "hard_negative_and_miss_ledger",
    "sensor_health_and_tamper",
    "multi_source_corroboration",
}

step_rows = []
for idx, raw_line in enumerate(steps_jsonl.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw_line.strip():
        continue
    row = json.loads(raw_line)
    if row.get("laneId") != "QL-THREAT-001":
        print(f"[FAIL] line {idx}: wrong laneId {row.get('laneId')}", file=sys.stderr)
        sys.exit(2)
    if row.get("status") != "passed":
        print(f"[FAIL] line {idx}: non-passing step status {row.get('status')}", file=sys.stderr)
        sys.exit(1)
    log_name = row.get("logFile")
    if (
        not isinstance(log_name, str)
        or not log_name
        or "/" in log_name
        or "\\" in log_name
        or ".." in log_name
        or pathlib.Path(log_name).name != log_name
    ):
        print(f"[FAIL] line {idx}: unsafe step log filename {log_name!r}", file=sys.stderr)
        sys.exit(2)
    log_path = run_dir / log_name
    if log_path.is_symlink() or not log_path.is_file() or log_path.resolve().parent != run_dir_resolved:
        print(f"[FAIL] line {idx}: missing or escaped step log artifact {log_name!r}", file=sys.stderr)
        sys.exit(2)
    log_bytes = log_path.read_bytes()
    actual_digest = "sha256:" + hashlib.sha256(log_bytes).hexdigest()
    if actual_digest != row.get("outputDigest"):
        print(f"[FAIL] line {idx}: log digest mismatch ({actual_digest} != {row.get('outputDigest')})", file=sys.stderr)
        sys.exit(2)
    text_sample = log_bytes.decode("utf-8", errors="replace")
    for marker in SECRET_MARKERS:
        if marker in text_sample:
            print(f"[FAIL] line {idx}: secret marker detected in diagnostic log {log_name}", file=sys.stderr)
            sys.exit(3)
    step_rows.append(row)

if len(step_rows) != len(commands):
    print(f"[FAIL] step count ({len(step_rows)}) disagrees with receipt command count ({len(commands)})", file=sys.stderr)
    sys.exit(2)

observed_ids = [row.get("stepId") for row in step_rows]
if allow_static_only:
    if observed_ids != STATIC_STEP_IDS and observed_ids != FULL_STEP_IDS:
        print(f"[FAIL] static-only verification expected {STATIC_STEP_IDS} or full set, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
else:
    if observed_ids != FULL_STEP_IDS:
        print(f"[FAIL] incomplete QL-THREAT-001 receipt: expected all {len(FULL_STEP_IDS)} steps, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
    observed_pillars = {row.get("pillar") for row in step_rows}
    if observed_pillars != REQUIRED_FULL_PILLARS:
        print(f"[FAIL] missing required threat pillars: {REQUIRED_FULL_PILLARS - observed_pillars}", file=sys.stderr)
        sys.exit(2)

for idx, (cmd, row) in enumerate(zip(commands, step_rows), start=1):
    if cmd.get("argv") != row.get("argv"):
        print(f"[FAIL] command {idx} argv disagrees with threat-steps.jsonl", file=sys.stderr)
        sys.exit(2)
    if cmd.get("status") != "passed":
        print(f"[FAIL] command {idx} non-passing status: {cmd.get('status')}", file=sys.stderr)
        sys.exit(1)
    if cmd.get("outputDigest") != row.get("outputDigest"):
        print(f"[FAIL] command {idx} outputDigest disagrees with threat-steps.jsonl", file=sys.stderr)
        sys.exit(2)

mode_label = "static-only" if observed_ids == STATIC_STEP_IDS else "full-5-pillar"
print(f"[PASS] QL-THREAT-001 standalone verifier ({mode_label}): {len(step_rows)} steps, 0 secret leaks, all digests verified")
PY
fi

cd "$ROOT"

if ((SIMULATE_MISSING_PREREQ)); then
  printf '{"laneId":"%s","status":"unavailable_prerequisite","reason":"simulated_missing_prerequisite","guidance":"install_pinned_toolchain_and_retry"}\n' "$LANE_ID" >&2
  exit 5
fi

TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]] && command -v rustup >/dev/null 2>&1; then
  CARGO_CMD=(rustup run "$TOOLCHAIN" cargo --offline)
elif command -v cargo >/dev/null 2>&1; then
  CARGO_CMD=(cargo --offline)
else
  printf '{"laneId":"%s","status":"unavailable_prerequisite","reason":"cargo_unavailable","guidance":"provision_pinned_nightly_toolchain"}\n' "$LANE_ID" >&2
  exit 5
fi

started_ns="$(python3 -c 'import time; print(time.time_ns())')"
if [[ -z "$RECEIPT_DIR" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-threat")"
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")"
fi

records="$RECEIPT_DIR/commands.jsonl"
steps_log="$RECEIPT_DIR/threat-steps.jsonl"
: > "$steps_log"
overall_status="passed"

run_step() {
  local step_id="$1"
  local pillar="$2"
  shift 2
  local log_name="${step_id}.log"
  local log_path="$RECEIPT_DIR/$log_name"
  local t0 t1 dur_ms rc status digest

  t0="$(python3 -c 'import time; print(time.time_ns())')"
  set +e
  "$@" > "$log_path" 2>&1
  rc=$?
  set -e
  t1="$(python3 -c 'import time; print(time.time_ns())')"
  dur_ms=$(( (t1 - t0) / 1000000 ))
  digest="sha256:$(python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$log_path")"

  if ((rc == 0)); then
    status="passed"
  else
    status="failed"
    overall_status="failed"
  fi

  python3 - "$records" "$steps_log" "$LANE_ID" "$step_id" "$pillar" "$status" "$digest" "$log_name" "$dur_ms" "$@" <<'PY'
import json, os, pathlib, sys
rec_path, step_path, lane_id, step_id, pillar, status, digest, log_name, dur_ms = sys.argv[1:10]
argv = sys.argv[10:]
with pathlib.Path(rec_path).open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({"id": step_id, "status": status, "outputDigest": digest, "argv": argv}, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
with pathlib.Path(step_path).open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "laneId": lane_id,
        "stepId": step_id,
        "pillar": pillar,
        "status": status,
        "outputDigest": digest,
        "logFile": log_name,
        "durationMs": int(dur_ms),
        "argv": argv,
        "guidance": "none" if status == "passed" else "inspect_step_log_and_repair_threat_corroboration",
    }, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
PY

  if ((rc != 0)); then
    printf '[FAIL] %s (%s/%s) — see %s\n' "$LANE_ID" "$pillar" "$step_id" "$log_path" >&2
    return 0
  fi
  printf '[PASS] %s (%s/%s) %s (%dms)\n' "$LANE_ID" "$pillar" "$step_id" "$digest" "$dur_ms" >&2
}

# Static threat schema and registry consistency checks.
run_step "thr-01-threat-schema-constitution" "calibration_and_alert_budget" python3 scripts/schema_validate.py
run_step "thr-02-threat-registry-consistency" "calibration_and_alert_budget" python3 scripts/architecture_registry_consistency.py

if ((ONLY_STATIC == 0)); then
  run_step "thr-03-conformal-eprocess-and-fusion" "calibration_and_alert_budget" \
    "${CARGO_CMD[@]}" test --locked -p fss-fusion --lib \
      --test fusion_contract \
      --test ablation_contract
  run_step "thr-04-shared-failure-domain-dsep" "independence_and_failure_domains" \
    "${CARGO_CMD[@]}" test --locked -p fss-graph-algorithms \
      --test fss_161_d_separation_failure_domains_contract
  run_step "thr-05-calibration-invalidation-and-cascade" "hard_negative_and_miss_ledger" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test corroboration_dependencies_contract \
      --test calibration_invalidation_contract \
      --test calibration_invalidation_coverage_contract \
      --test detector_cascade_contract \
      --test detector_cascade_recovery_contract
  run_step "thr-06-sensor-tamper-and-health-coverage" "sensor_health_and_tamper" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test sensor_tamper_stickiness_contract
  run_step "thr-07-corroboration-and-health-cli-e2e" "multi_source_corroboration" \
    "${CARGO_CMD[@]}" test --locked -p fss-cli \
      --test corroborate_cli_contract \
      --test corroborate_fusion_cli_contract \
      --test corroborate_stream_cli \
      --test corroborate_stream_detector_cli \
      --test corroborate_stream_geometry_cli \
      --test historical_health_corroboration_cli \
      --test recorded_health_cli_contract \
      --test watch_stream_health_cli
fi

finished_ns="$(python3 -c 'import time; print(time.time_ns())')"
source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
sibling_digest="${FSS_DSR_SIBLING_CLOSURE_DIGEST:-$(python3 "$ROOT/scripts/sibling_closure.py" "$ROOT")}"
host_digest="sha256:$(python3 -c 'import hashlib, os, platform; print(hashlib.sha256("|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")]).encode()).hexdigest())')"
target="${FSS_TARGET_TRIPLE:-$(uname -s)-$(uname -m)}"
manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1 || true)"
[[ -n "$manifest_root" ]] || manifest_root="unavailable"

receipt_path="$RECEIPT_DIR/threat-receipt.json"
receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
  --output "$receipt_path" --records "$records" --lane "$LANE_NAME" \
  --source-commit "$source_commit" --source-tree "$source_tree" \
  --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
  --toolchain "${TOOLCHAIN:-unavailable}" --target "$target" \
  --started-ns "$started_ns" --finished-ns "$finished_ns" \
  --status "$overall_status" --manifest-root "$manifest_root" \
  --cargo-lock "$ROOT/Cargo.lock")"

printf 'QL-THREAT-001 receipt: %s (status=%s)\n' "$receipt_path" "$receipt_status" >&2
[[ "$receipt_status" == "passed" ]]
