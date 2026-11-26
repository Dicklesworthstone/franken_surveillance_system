#!/usr/bin/env bash
# QL-SECURITY-001 — Reusable local qualification lane: security/privacy (`fss-x4a.29.18`).
#
# Exact scope (`docs/LOCAL_QUALIFICATION_WITH_DSR.md`):
#   1. capability_non_escalation  — semantic plane isolation, #![forbid(unsafe_code)], Asupersync guard,
#                                   ledger authority/plane isolation, graph pre-expansion redaction
#   2. secret_redaction           — encrypted local vault scope isolation, zeroization, canary leak scans
#   3. parser_resource_bounds     — bounded canonical decoders & hostile wire fail-closed contracts
#   4. sandboxing_runtime_isolation — lab-oracle absence, foreign model runtime absence, adapter boundary
#   5. mask_before_publication    — privacy mask-before-egress CLI & redaction contract
#   6. retention_and_deletion     — conservative retention/hold lattice (FSS-036) & deletion closure (FSS-133)
#
# Never contacts external providers or networks (`CARGO_NET_OFFLINE=true`).
# Never upgrades a skipped, unavailable, or failed check into a pass.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE_ID="QL-SECURITY-001"
LANE_NAME="security"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/lanes/security.sh [--list] [--receipt-dir DIR]
                                 [--verify-receipt RECEIPT_JSON [--allow-static-only]]
                                 [--only-static] [--dry-run-missing-prereq]
USAGE
}

MODE="run"
RECEIPT_DIR="${FSS_SECURITY_RECEIPT_DIR:-}"
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
    *) printf 'QL-SECURITY-001: unknown argument: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

declare -a STEP_IDS=(
  "sec-01-semantic-planes"
  "sec-02-unsafe-prohibition"
  "sec-03-asupersync-concurrency"
  "sec-04-lab-oracle-absence"
  "sec-05-foreign-runtime-absence"
  "sec-06-adapter-security-boundary"
  "sec-07-ledger-authority-isolation"
  "sec-08-graph-capability-redaction"
  "sec-09-vault-secret-containment"
  "sec-10-parser-and-wire-bounds"
  "sec-11-mask-before-publication"
  "sec-12-retention-holds"
  "sec-13-graph-complete-deletion"
)

declare -a STEP_PILLARS=(
  "capability_non_escalation"
  "capability_non_escalation"
  "capability_non_escalation"
  "sandboxing_runtime_isolation"
  "sandboxing_runtime_isolation"
  "sandboxing_runtime_isolation"
  "capability_non_escalation"
  "capability_non_escalation"
  "secret_redaction"
  "parser_resource_bounds"
  "mask_before_publication"
  "retention_and_deletion"
  "retention_and_deletion"
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
    print(f"[FAIL] QL-SECURITY-001 verifier: receipt missing: {receipt_path}", file=sys.stderr)
    sys.exit(2)

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] QL-SECURITY-001 verifier: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if receipt.get("schema") != "fss.release_qualification_receipt.v1":
    print(f"[FAIL] unexpected schema: {receipt.get('schema')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("laneId") != "QL-SECURITY-001":
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
steps_jsonl = run_dir / "security-steps.jsonl"
if not steps_jsonl.is_file():
    print(f"[FAIL] missing structured step log: {steps_jsonl}", file=sys.stderr)
    sys.exit(2)

SECRET_MARKERS = ("BEGIN PRIVATE KEY", "AKIA", "rtsp-pass-gen1", "password=", "Authorization: Bearer ")
FULL_STEP_IDS = [
    "sec-01-semantic-planes",
    "sec-02-unsafe-prohibition",
    "sec-03-asupersync-concurrency",
    "sec-04-lab-oracle-absence",
    "sec-05-foreign-runtime-absence",
    "sec-06-adapter-security-boundary",
    "sec-07-ledger-authority-isolation",
    "sec-08-graph-capability-redaction",
    "sec-09-vault-secret-containment",
    "sec-10-parser-and-wire-bounds",
    "sec-11-mask-before-publication",
    "sec-12-retention-holds",
    "sec-13-graph-complete-deletion",
]
STATIC_STEP_IDS = FULL_STEP_IDS[:6]
REQUIRED_FULL_PILLARS = {
    "capability_non_escalation",
    "secret_redaction",
    "parser_resource_bounds",
    "sandboxing_runtime_isolation",
    "mask_before_publication",
    "retention_and_deletion",
}

step_rows = []
for idx, raw_line in enumerate(steps_jsonl.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw_line.strip():
        continue
    row = json.loads(raw_line)
    if row.get("laneId") != "QL-SECURITY-001":
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
        print(f"[FAIL] incomplete QL-SECURITY-001 receipt: expected all {len(FULL_STEP_IDS)} steps, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
    observed_pillars = {row.get("pillar") for row in step_rows}
    if observed_pillars != REQUIRED_FULL_PILLARS:
        print(f"[FAIL] missing required security pillars: {REQUIRED_FULL_PILLARS - observed_pillars}", file=sys.stderr)
        sys.exit(2)

for idx, (cmd, row) in enumerate(zip(commands, step_rows), start=1):
    if cmd.get("argv") != row.get("argv"):
        print(f"[FAIL] command {idx} argv disagrees with security-steps.jsonl", file=sys.stderr)
        sys.exit(2)
    if cmd.get("status") != "passed":
        print(f"[FAIL] command {idx} non-passing status: {cmd.get('status')}", file=sys.stderr)
        sys.exit(1)
    if cmd.get("outputDigest") != row.get("outputDigest"):
        print(f"[FAIL] command {idx} outputDigest disagrees with security-steps.jsonl", file=sys.stderr)
        sys.exit(2)

mode_label = "static-only" if observed_ids == STATIC_STEP_IDS else "full-6-pillar"
print(f"[PASS] QL-SECURITY-001 standalone verifier ({mode_label}): {len(step_rows)} steps, 0 secret leaks, all digests verified")
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
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-security")"
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")"
fi

records="$RECEIPT_DIR/commands.jsonl"
steps_log="$RECEIPT_DIR/security-steps.jsonl"
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
        "guidance": "none" if status == "passed" else "inspect_step_log_and_repair_security_invariant",
    }, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
PY

  if ((rc != 0)); then
    printf '[FAIL] %s (%s/%s) — see %s\n' "$LANE_ID" "$pillar" "$step_id" "$log_path" >&2
    return 0
  fi
  printf '[PASS] %s (%s/%s) %s (%dms)\n' "$LANE_ID" "$pillar" "$step_id" "$digest" "$dur_ms" >&2
}

# Static security/privacy constitution checks (fast, hermetic, always run).
run_step "sec-01-semantic-planes" "capability_non_escalation" python3 scripts/semantic_plane_checker.py
run_step "sec-02-unsafe-prohibition" "capability_non_escalation" python3 scripts/unsafe_prohibition_checker.py
run_step "sec-03-asupersync-concurrency" "capability_non_escalation" python3 scripts/asupersync_concurrency_guard.py
run_step "sec-04-lab-oracle-absence" "sandboxing_runtime_isolation" python3 scripts/lab_oracle_absence.py
run_step "sec-05-foreign-runtime-absence" "sandboxing_runtime_isolation" python3 scripts/foreign_model_runtime_absence.py
run_step "sec-06-adapter-security-boundary" "sandboxing_runtime_isolation" python3 scripts/standards_first_adapter_checker.py

if ((ONLY_STATIC == 0)); then
  run_step "sec-07-ledger-authority-isolation" "capability_non_escalation" \
    "${CARGO_CMD[@]}" test --locked -p fss-ledger \
      --test fss_031_frankensqlite_storage_trait_contract \
      --test fss_032_frankensqlite_api_qualification_contract
  run_step "sec-08-graph-capability-redaction" "capability_non_escalation" \
    "${CARGO_CMD[@]}" test --locked -p fss-graph-algorithms \
      --test fss_151_immutable_projection_contract \
      --test fss_161_d_separation_failure_domains_contract
  run_step "sec-09-vault-secret-containment" "secret_redaction" \
    "${CARGO_CMD[@]}" test --locked -p fss-vault --test vault_security_contract
  run_step "sec-10-parser-and-wire-bounds" "parser_resource_bounds" \
    "${CARGO_CMD[@]}" test --locked -p fss-core \
      --test durable_format_contract \
      --test knowledge_cell_decode_refusal_contract \
      --test agent_contracts_contract \
      --test world_fact_authority_guard_contract
  run_step "sec-11-mask-before-publication" "mask_before_publication" \
    "${CARGO_CMD[@]}" test --locked -p fss-cli --test privacy_mask_cli_contract
  run_step "sec-12-retention-holds" "retention_and_deletion" \
    "${CARGO_CMD[@]}" test --locked -p fss-ledger --test fss_036_retention_hold_tables_contract
  run_step "sec-13-graph-complete-deletion" "retention_and_deletion" \
    "${CARGO_CMD[@]}" test --locked -p fss-object --test fss_133_graph_complete_deletion_contract
fi

finished_ns="$(python3 -c 'import time; print(time.time_ns())')"
source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
sibling_digest="${FSS_DSR_SIBLING_CLOSURE_DIGEST:-$(python3 "$ROOT/scripts/sibling_closure.py" "$ROOT")}"
host_digest="sha256:$(python3 -c 'import hashlib, os, platform; print(hashlib.sha256("|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")]).encode()).hexdigest())')"
target="${FSS_TARGET_TRIPLE:-$(uname -s)-$(uname -m)}"
manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1 || true)"
[[ -n "$manifest_root" ]] || manifest_root="unavailable"

receipt_path="$RECEIPT_DIR/security-receipt.json"
receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
  --output "$receipt_path" --records "$records" --lane "$LANE_NAME" \
  --source-commit "$source_commit" --source-tree "$source_tree" \
  --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
  --toolchain "${TOOLCHAIN:-unavailable}" --target "$target" \
  --started-ns "$started_ns" --finished-ns "$finished_ns" \
  --status "$overall_status" --manifest-root "$manifest_root" \
  --cargo-lock "$ROOT/Cargo.lock")"

printf 'QL-SECURITY-001 receipt: %s (status=%s)\n' "$receipt_path" "$receipt_status" >&2
[[ "$receipt_status" == "passed" ]]
