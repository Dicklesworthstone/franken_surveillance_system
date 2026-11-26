#!/usr/bin/env bash
# QL-REFERENCE-001 — Reusable local qualification lane: reference semantics (`fss-x4a.29.17`).
#
# Exact scope (`docs/LOCAL_QUALIFICATION_WITH_DSR.md`):
#   Runs deterministic single-threaded (`RUST_TEST_THREADS=1`) ledger/object/graph/event/model/container
#   oracles and golden traces, plus static schema/registry/DAG constitution proofs.
#
# Never contacts external providers or networks (`CARGO_NET_OFFLINE=true`).
# Never upgrades a skipped, unavailable, or failed check into a pass.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE_ID="QL-REFERENCE-001"
LANE_NAME="reference"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RUST_TEST_THREADS=1
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/lanes/reference.sh [--list] [--receipt-dir DIR]
                                  [--verify-receipt RECEIPT_JSON [--allow-static-only]]
                                  [--only-static] [--dry-run-missing-prereq]
USAGE
}

MODE="run"
RECEIPT_DIR="${FSS_REFERENCE_RECEIPT_DIR:-}"
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
    *) printf 'QL-REFERENCE-001: unknown argument: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

declare -a STEP_IDS=(
  "ref-01-schema-constitution"
  "ref-02-registry-consistency"
  "ref-03-dependency-dag"
  "ref-04-ledger-oracle"
  "ref-05-object-oracle"
  "ref-06-graph-oracle"
  "ref-07-core-contract-oracle"
  "ref-08-model-reference-oracle"
  "ref-09-container-golden-oracle"
)

declare -a STEP_PILLARS=(
  "schema_and_golden_registry"
  "schema_and_golden_registry"
  "schema_and_golden_registry"
  "ledger_oracle"
  "object_oracle"
  "graph_oracle"
  "event_and_model_oracle"
  "event_and_model_oracle"
  "event_and_model_oracle"
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
    print(f"[FAIL] QL-REFERENCE-001 verifier: receipt missing: {receipt_path}", file=sys.stderr)
    sys.exit(2)

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] QL-REFERENCE-001 verifier: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if receipt.get("schema") != "fss.release_qualification_receipt.v1":
    print(f"[FAIL] unexpected schema: {receipt.get('schema')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("laneId") != "QL-REFERENCE-001":
    print(f"[FAIL] unexpected laneId: {receipt.get('laneId')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("status") != "passed":
    print(f"[FAIL] non-passing receipt status: {receipt.get('status')}", file=sys.stderr)
    sys.exit(1)

commands = receipt.get("commands")
if not isinstance(commands, list) or not commands:
    print("[FAIL] empty command record set", file=sys.stderr)
    sys.exit(2)

run_dir = receipt_path.parent
steps_jsonl = run_dir / "reference-steps.jsonl"
if not steps_jsonl.is_file():
    print(f"[FAIL] missing structured step log: {steps_jsonl}", file=sys.stderr)
    sys.exit(2)

SECRET_MARKERS = ("BEGIN PRIVATE KEY", "AKIA", "rtsp-pass-gen1", "password=", "Authorization: Bearer ")
FULL_STEP_IDS = [
    "ref-01-schema-constitution",
    "ref-02-registry-consistency",
    "ref-03-dependency-dag",
    "ref-04-ledger-oracle",
    "ref-05-object-oracle",
    "ref-06-graph-oracle",
    "ref-07-core-contract-oracle",
    "ref-08-model-reference-oracle",
    "ref-09-container-golden-oracle",
]
STATIC_STEP_IDS = FULL_STEP_IDS[:3]
REQUIRED_FULL_PILLARS = {
    "schema_and_golden_registry",
    "ledger_oracle",
    "object_oracle",
    "graph_oracle",
    "event_and_model_oracle",
}

step_rows = []
for idx, raw_line in enumerate(steps_jsonl.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw_line.strip():
        continue
    row = json.loads(raw_line)
    if row.get("laneId") != "QL-REFERENCE-001":
        print(f"[FAIL] line {idx}: wrong laneId {row.get('laneId')}", file=sys.stderr)
        sys.exit(2)
    if row.get("status") != "passed":
        print(f"[FAIL] line {idx}: non-passing step status {row.get('status')}", file=sys.stderr)
        sys.exit(1)
    log_name = row.get("logFile")
    if not log_name or not (run_dir / log_name).is_file():
        print(f"[FAIL] line {idx}: missing step log artifact {log_name}", file=sys.stderr)
        sys.exit(2)
    log_bytes = (run_dir / log_name).read_bytes()
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
        print(f"[FAIL] incomplete QL-REFERENCE-001 receipt: expected all {len(FULL_STEP_IDS)} steps, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
    observed_pillars = {row.get("pillar") for row in step_rows}
    if observed_pillars != REQUIRED_FULL_PILLARS:
        print(f"[FAIL] missing required reference pillars: {REQUIRED_FULL_PILLARS - observed_pillars}", file=sys.stderr)
        sys.exit(2)

for idx, (cmd, row) in enumerate(zip(commands, step_rows), start=1):
    if cmd.get("argv") != row.get("argv"):
        print(f"[FAIL] command {idx} argv disagrees with reference-steps.jsonl", file=sys.stderr)
        sys.exit(2)
    if cmd.get("status") != "passed":
        print(f"[FAIL] command {idx} non-passing status: {cmd.get('status')}", file=sys.stderr)
        sys.exit(1)
    if cmd.get("outputDigest") != row.get("outputDigest"):
        print(f"[FAIL] command {idx} outputDigest disagrees with reference-steps.jsonl", file=sys.stderr)
        sys.exit(2)

mode_label = "static-only" if observed_ids == STATIC_STEP_IDS else "full-single-threaded-oracle"
print(f"[PASS] QL-REFERENCE-001 standalone verifier ({mode_label}): {len(step_rows)} steps, 0 secret leaks, all digests verified")
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
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-reference")"
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")"
fi

records="$RECEIPT_DIR/commands.jsonl"
steps_log="$RECEIPT_DIR/reference-steps.jsonl"
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
        "guidance": "none" if status == "passed" else "inspect_step_log_and_repair_reference_oracle",
    }, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
PY

  if ((rc != 0)); then
    printf '[FAIL] %s (%s/%s) — see %s\n' "$LANE_ID" "$pillar" "$step_id" "$log_path" >&2
    return 0
  fi
  printf '[PASS] %s (%s/%s) %s (%dms)\n' "$LANE_ID" "$pillar" "$step_id" "$digest" "$dur_ms" >&2
}

# Static schema, registry, and dependency DAG reference invariants.
run_step "ref-01-schema-constitution" "schema_and_golden_registry" python3 scripts/schema_validate.py
run_step "ref-02-registry-consistency" "schema_and_golden_registry" python3 scripts/architecture_registry_consistency.py
run_step "ref-03-dependency-dag" "schema_and_golden_registry" python3 scripts/dependency_dag_checker.py

if ((ONLY_STATIC == 0)); then
  run_step "ref-04-ledger-oracle" "ledger_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-ledger \
      --test ledger_oracle_contract \
      --test merkle_property_oracle_contract \
      --test fss_102_replay_cursor_contract \
      --test fss_106_ssi_phantom_corpus_contract
  run_step "ref-05-object-oracle" "object_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-object \
      --test oracle_family \
      --test fss_127_object_graph_closure_contract \
      --test fss_135_independent_reconstruction_contract
  run_step "ref-06-graph-oracle" "graph_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-graph-algorithms \
      --test fss_151_immutable_projection_contract \
      --test fss_153_canonical_graph_serialization_contract \
      --test fss_161_d_separation_failure_domains_contract \
      --test fss_162_factorized_query_planner_contract
  run_step "ref-07-core-contract-oracle" "event_and_model_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-core \
      --test contract_property_family
  run_step "ref-08-model-reference-oracle" "event_and_model_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-reference \
      --test fss_139_scalar_detector_executor_contract \
      --test fss_143_preprocess_postprocess_fusion_contract \
      --test fss_150_thermal_pressure_scheduler_contract
  run_step "ref-09-container-golden-oracle" "event_and_model_oracle" \
    env RUST_TEST_THREADS=1 "${CARGO_CMD[@]}" test --locked -p fss-container \
      --test avc_mux_contract \
      --test fss_115_fragmented_mp4_cmaf_contract
fi

finished_ns="$(python3 -c 'import time; print(time.time_ns())')"
source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
sibling_digest="${FSS_DSR_SIBLING_CLOSURE_DIGEST:-$(python3 "$ROOT/scripts/sibling_closure.py" "$ROOT")}"
host_digest="sha256:$(python3 -c 'import hashlib, os, platform; print(hashlib.sha256("|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")]).encode()).hexdigest())')"
target="${FSS_TARGET_TRIPLE:-$(uname -s)-$(uname -m)}"
manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1 || true)"
[[ -n "$manifest_root" ]] || manifest_root="unavailable"

receipt_path="$RECEIPT_DIR/reference-receipt.json"
receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
  --output "$receipt_path" --records "$records" --lane "$LANE_NAME" \
  --source-commit "$source_commit" --source-tree "$source_tree" \
  --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
  --toolchain "${TOOLCHAIN:-unavailable}" --target "$target" \
  --started-ns "$started_ns" --finished-ns "$finished_ns" \
  --status "$overall_status" --manifest-root "$manifest_root" \
  --cargo-lock "$ROOT/Cargo.lock")"

printf 'QL-REFERENCE-001 receipt: %s (status=%s)\n' "$receipt_path" "$receipt_status" >&2
[[ "$receipt_status" == "passed" ]]
