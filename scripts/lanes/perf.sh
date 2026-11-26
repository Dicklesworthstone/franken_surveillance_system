#!/usr/bin/env bash
# QL-PERF-001 — Reusable local qualification lane: performance/energy (`fss-x4a.29.19`).
#
# Exact scope (`docs/LOCAL_QUALIFICATION_WITH_DSR.md`):
#   1. workload_manifest_and_thresholds — SLO registry, workload manifest, operation-cost regression bounds
#   2. same_binary_aa_ab                — same-binary A/A determinism and A/B labeled comparison receipts (FSS-196)
#   3. semantic_digest_parity           — SIMD/packed/tiled kernel bit-exact parity against scalar oracles (FSS-123/141/142)
#   4. percentile_distributions         — fused scratch/memory savings, bounded scale latency & percentile witness (FSS-140/143)
#   5. thermal_energy_counters          — thermal/pressure hard-floor model scheduler & honest host telemetry probe (FSS-150)
#
# Never contacts external providers or networks (`CARGO_NET_OFFLINE=true`).
# Never upgrades a skipped, unavailable, or failed check into a pass.
# Never fabricates privileged hardware power/thermal readings when unprivileged.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE_ID="QL-PERF-001"
LANE_NAME="perf"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/lanes/perf.sh [--list] [--receipt-dir DIR]
                             [--verify-receipt RECEIPT_JSON [--allow-static-only]]
                             [--only-static] [--dry-run-missing-prereq]
USAGE
}

MODE="run"
RECEIPT_DIR="${FSS_PERF_RECEIPT_DIR:-}"
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
    *) printf 'QL-PERF-001: unknown argument: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

declare -a STEP_IDS=(
  "perf-01-workload-manifest-slo"
  "perf-02-operation-cost-thresholds"
  "perf-03-same-binary-aa-ab-receipts"
  "perf-04-simd-semantic-parity-aa-ab"
  "perf-05-kernel-dispatch-and-packed-matmul"
  "perf-06-fusion-memory-bandwidth"
  "perf-07-thermal-energy-floors"
  "perf-08-scale-percentile-witness"
)

declare -a STEP_PILLARS=(
  "workload_manifest_and_thresholds"
  "workload_manifest_and_thresholds"
  "same_binary_aa_ab"
  "semantic_digest_parity"
  "semantic_digest_parity"
  "percentile_distributions"
  "thermal_energy_counters"
  "percentile_distributions"
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
import math
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
allow_static_only = sys.argv[2] == "1"
if receipt_path.is_symlink() or not receipt_path.is_file():
    print(f"[FAIL] QL-PERF-001 verifier: receipt missing or symlinked: {receipt_path}", file=sys.stderr)
    sys.exit(2)

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] QL-PERF-001 verifier: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if receipt.get("schema") != "fss.release_qualification_receipt.v1":
    print(f"[FAIL] unexpected schema: {receipt.get('schema')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("laneId") != "QL-PERF-001":
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
steps_jsonl = run_dir / "perf-steps.jsonl"
if steps_jsonl.is_symlink() or not steps_jsonl.is_file():
    print(f"[FAIL] missing or symlinked structured step log: {steps_jsonl}", file=sys.stderr)
    sys.exit(2)

metrics_path = run_dir / "perf-metrics.json"
if metrics_path.is_symlink() or not metrics_path.is_file():
    print(f"[FAIL] missing or symlinked perf metrics summary: {metrics_path}", file=sys.stderr)
    sys.exit(2)
try:
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] invalid perf-metrics.json: {exc}", file=sys.stderr)
    sys.exit(2)
if metrics.get("schema") != "fss.perf_lane_metrics.v1" or metrics.get("laneId") != "QL-PERF-001":
    print(f"[FAIL] unexpected perf-metrics header: {metrics.get('schema')} / {metrics.get('laneId')}", file=sys.stderr)
    sys.exit(2)

SECRET_MARKERS = ("BEGIN PRIVATE KEY", "AKIA", "rtsp-pass-gen1", "password=", "Authorization: Bearer ")
FULL_STEP_IDS = [
    "perf-01-workload-manifest-slo",
    "perf-02-operation-cost-thresholds",
    "perf-03-same-binary-aa-ab-receipts",
    "perf-04-simd-semantic-parity-aa-ab",
    "perf-05-kernel-dispatch-and-packed-matmul",
    "perf-06-fusion-memory-bandwidth",
    "perf-07-thermal-energy-floors",
    "perf-08-scale-percentile-witness",
]
STATIC_STEP_IDS = FULL_STEP_IDS[:2]
REQUIRED_FULL_PILLARS = {
    "workload_manifest_and_thresholds",
    "same_binary_aa_ab",
    "semantic_digest_parity",
    "percentile_distributions",
    "thermal_energy_counters",
}

step_rows = []
for idx, raw_line in enumerate(steps_jsonl.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw_line.strip():
        continue
    row = json.loads(raw_line)
    if row.get("laneId") != "QL-PERF-001":
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
if metrics.get("stepCount") != len(step_rows):
    print(f"[FAIL] perf-metrics stepCount ({metrics.get('stepCount')}) != step rows ({len(step_rows)})", file=sys.stderr)
    sys.exit(2)
durations = []
for idx, row in enumerate(step_rows, start=1):
    d = row.get("durationMs")
    if not isinstance(d, int) or isinstance(d, bool) or d < 0:
        print(f"[FAIL] line {idx}: malformed durationMs {d!r}", file=sys.stderr)
        sys.exit(2)
    durations.append(d)
durations.sort()

def _pct(vals, q):
    if not vals:
        return 0
    i = min(len(vals) - 1, max(0, math.ceil(q * len(vals)) - 1))
    return vals[i]

expected_percentiles = {
    "p50": _pct(durations, 0.50),
    "p95": _pct(durations, 0.95),
    "p99": _pct(durations, 0.99),
    "total": sum(durations),
}
percentiles = metrics.get("stepDurationPercentilesMs")
if not isinstance(percentiles, dict) or percentiles != expected_percentiles:
    print(
        f"[FAIL] stepDurationPercentilesMs mismatch: got {percentiles!r}, expected {expected_percentiles!r}",
        file=sys.stderr,
    )
    sys.exit(2)
manifest_digest = metrics.get("workloadManifestDigest")
manifest_files = metrics.get("workloadManifestFiles")
if (
    not isinstance(manifest_digest, str)
    or not manifest_digest.startswith("sha256:")
    or len(manifest_digest) != 71
    or any(ch not in "0123456789abcdef" for ch in manifest_digest[7:])
    or not isinstance(manifest_files, list)
    or not manifest_files
):
    print("[FAIL] malformed workload manifest witness in perf-metrics.json", file=sys.stderr)
    sys.exit(2)
thermal = metrics.get("thermalEnergyCounters")
want_sched_ok = any(r.get("stepId") == "perf-07-thermal-energy-floors" and r.get("status") == "passed" for r in step_rows)
if (
    not isinstance(thermal, dict)
    or not isinstance(thermal.get("status"), str)
    or thermal.get("deterministicSchedulerContractVerified") is not want_sched_ok
):
    print(f"[FAIL] thermalEnergyCounters witness disagrees with executed steps: {thermal!r}", file=sys.stderr)
    sys.exit(2)

observed_ids = [row.get("stepId") for row in step_rows]
if allow_static_only:
    if observed_ids != STATIC_STEP_IDS and observed_ids != FULL_STEP_IDS:
        print(f"[FAIL] static-only verification expected {STATIC_STEP_IDS} or full set, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
else:
    if observed_ids != FULL_STEP_IDS:
        print(f"[FAIL] incomplete QL-PERF-001 receipt: expected all {len(FULL_STEP_IDS)} steps, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
    observed_pillars = {row.get("pillar") for row in step_rows}
    if observed_pillars != REQUIRED_FULL_PILLARS:
        print(f"[FAIL] missing required perf pillars: {REQUIRED_FULL_PILLARS - observed_pillars}", file=sys.stderr)
        sys.exit(2)

for idx, (cmd, row) in enumerate(zip(commands, step_rows), start=1):
    if cmd.get("argv") != row.get("argv"):
        print(f"[FAIL] command {idx} argv disagrees with perf-steps.jsonl", file=sys.stderr)
        sys.exit(2)
    if cmd.get("status") != "passed":
        print(f"[FAIL] command {idx} non-passing status: {cmd.get('status')}", file=sys.stderr)
        sys.exit(1)
    if cmd.get("outputDigest") != row.get("outputDigest"):
        print(f"[FAIL] command {idx} outputDigest disagrees with perf-steps.jsonl", file=sys.stderr)
        sys.exit(2)

mode_label = "static-only" if observed_ids == STATIC_STEP_IDS else "full-5-pillar"
print(
    f"[PASS] QL-PERF-001 standalone verifier ({mode_label}): "
    f"{len(step_rows)} steps, p50={percentiles['p50']}ms p95={percentiles['p95']}ms p99={percentiles['p99']}ms, "
    f"0 secret leaks, all digests verified"
)
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
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-perf")"
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")"
fi

records="$RECEIPT_DIR/commands.jsonl"
steps_log="$RECEIPT_DIR/perf-steps.jsonl"
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
        "guidance": "none" if status == "passed" else "inspect_step_log_and_repair_perf_regression",
    }, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
PY

  if ((rc != 0)); then
    printf '[FAIL] %s (%s/%s) — see %s\n' "$LANE_ID" "$pillar" "$step_id" "$log_path" >&2
    return 0
  fi
  printf '[PASS] %s (%s/%s) %s (%dms)\n' "$LANE_ID" "$pillar" "$step_id" "$digest" "$dur_ms" >&2
}

# Static workload manifest, SLO regression thresholds, and operation-cost table constitution.
run_step "perf-01-workload-manifest-slo" "workload_manifest_and_thresholds" python3 scripts/slo_validate.py
run_step "perf-02-operation-cost-thresholds" "workload_manifest_and_thresholds" python3 tests/test_slo_operation_cost_consistency.py

if ((ONLY_STATIC == 0)); then
  run_step "perf-03-same-binary-aa-ab-receipts" "same_binary_aa_ab" \
    "${CARGO_CMD[@]}" test --locked -p fss-core --test experiment_contract
  run_step "perf-04-simd-semantic-parity-aa-ab" "semantic_digest_parity" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference --test image_kernels_simd_contract
  run_step "perf-05-kernel-dispatch-and-packed-matmul" "semantic_digest_parity" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test fss_141_kernel_dispatch_receipts_contract \
      --test fss_142_packed_tiled_matrix_kernels_contract
  run_step "perf-06-fusion-memory-bandwidth" "percentile_distributions" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test fss_140_scratch_planner_contract \
      --test fss_143_preprocess_postprocess_fusion_contract
  run_step "perf-07-thermal-energy-floors" "thermal_energy_counters" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test fss_150_thermal_pressure_scheduler_contract
  run_step "perf-08-scale-percentile-witness" "percentile_distributions" \
    "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test agent_stores_scale_contract
fi

# Emit structured perf-metrics.json with workload manifest digest, step percentiles, and honest host telemetry state.
python3 - "$ROOT" "$steps_log" "$RECEIPT_DIR/perf-metrics.json" <<'PY'
import hashlib, json, math, os, pathlib, platform, sys

root = pathlib.Path(sys.argv[1])
steps_log = pathlib.Path(sys.argv[2])
out_path = pathlib.Path(sys.argv[3])

rows = [json.loads(line) for line in steps_log.read_text(encoding="utf-8").splitlines() if line.strip()]
durations = sorted(int(r.get("durationMs", 0)) for r in rows)

def pct(vals, q):
    if not vals:
        return 0
    idx = min(len(vals) - 1, max(0, math.ceil(q * len(vals)) - 1))
    return vals[idx]

manifest_hasher = hashlib.sha256()
manifest_files = []
for rel in ("registries/OPERATION_COSTS.md", "scripts/slo_validate.py"):
    p = root / rel
    if p.is_file():
        manifest_files.append(rel)
        manifest_hasher.update(rel.encode("utf-8") + b"\0" + p.read_bytes())

# Honest hardware thermal/energy telemetry disclosure (never fabricate privileged readings).
thermal_state = {
    "status": "unavailable_unprivileged_host",
    "platform": f"{platform.system()}-{platform.machine()}",
    "cpuCount": os.cpu_count(),
    "deterministicSchedulerContractVerified": any(
        r.get("stepId") == "perf-07-thermal-energy-floors" and r.get("status") == "passed" for r in rows
    ),
    "note": "Direct hardware RAPL/SMC energy counters require privileged host sensor entitlement; never synthesized.",
}

doc = {
    "schema": "fss.perf_lane_metrics.v1",
    "laneId": "QL-PERF-001",
    "stepCount": len(rows),
    "workloadManifestFiles": manifest_files,
    "workloadManifestDigest": "sha256:" + manifest_hasher.hexdigest(),
    "stepDurationPercentilesMs": {
        "p50": pct(durations, 0.50),
        "p95": pct(durations, 0.95),
        "p99": pct(durations, 0.99),
        "total": sum(durations),
    },
    "thermalEnergyCounters": thermal_state,
}
tmp = out_path.with_name(f".{out_path.name}.tmp.{os.getpid()}")
tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
os.replace(tmp, out_path)
PY

finished_ns="$(python3 -c 'import time; print(time.time_ns())')"
source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
sibling_digest="${FSS_DSR_SIBLING_CLOSURE_DIGEST:-$(python3 "$ROOT/scripts/sibling_closure.py" "$ROOT")}"
host_digest="sha256:$(python3 -c 'import hashlib, os, platform; print(hashlib.sha256("|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")]).encode()).hexdigest())')"
target="${FSS_TARGET_TRIPLE:-$(uname -s)-$(uname -m)}"
manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1 || true)"
[[ -n "$manifest_root" ]] || manifest_root="unavailable"

receipt_path="$RECEIPT_DIR/perf-receipt.json"
receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
  --output "$receipt_path" --records "$records" --lane "$LANE_NAME" \
  --source-commit "$source_commit" --source-tree "$source_tree" \
  --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
  --toolchain "${TOOLCHAIN:-unavailable}" --target "$target" \
  --started-ns "$started_ns" --finished-ns "$finished_ns" \
  --status "$overall_status" --manifest-root "$manifest_root" \
  --cargo-lock "$ROOT/Cargo.lock")"

printf 'QL-PERF-001 receipt: %s (status=%s)\n' "$receipt_path" "$receipt_status" >&2
[[ "$receipt_status" == "passed" ]]
