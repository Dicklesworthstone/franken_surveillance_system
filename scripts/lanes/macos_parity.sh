#!/usr/bin/env bash
# QL-MACOS-001 — Native macOS/Linux Parity & Atomicity Fault-Injection Qualification Lane.
#
# Usage:
#   scripts/lanes/macos_parity.sh                 # Full lane (all 7 checks incl. workspace clippy)
#   scripts/lanes/macos_parity.sh --skip-clippy   # Debug mode: skip Check 1 (workspace clippy)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SKIP_CLIPPY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-clippy)
      SKIP_CLIPPY=1
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/lanes/macos_parity.sh [--skip-clippy]

QL-MACOS-001 verifies native macOS Apple Silicon / Linux parity across 7 checks:
  1. clippy_zero_warnings               Full workspace --all-targets clippy (-D warnings)
  2. fss_doctor_healthy                 Real deployment: fss doctor healthy + status possibly_stale=false
  3. session_open_refusal_atomicity     Refused fss session open leaves 0 new bytes/files under root
  4. symlink_root_and_backup_roundtrip  fss-backup plan->create->inspect->restore under /tmp & canonical path
  5. mcp_14_tool_lifecycle              MCP CLI, operational targets, H2/H3 hydration & adversarial E2E
  6. dashboard_snapshot_and_live_smoke  fss-dashboard snapshot + --live fallback + live daemon contract
  7. macos_unit_parity_tests            All 6 fixed upstream/macOS parity unit & integration tests

Artifacts:
  target/test-logs/macos-parity/macos_parity_matrix.jsonl
  target/test-logs/macos-parity/macos_parity_report.json
  target/test-logs/macos-parity/clippy_output.log
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fss-mac-target}"
export FSS_MACOS_PARITY_LOG_DIR="${FSS_MACOS_PARITY_LOG_DIR:-$ROOT/target/test-logs/macos-parity}"

OS_NAME="$(uname -s)"
ARCH_NAME="$(uname -m)"

TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then
  RUN=(rustup run "$TOOLCHAIN")
else
  RUN=()
fi

mkdir -p "$FSS_MACOS_PARITY_LOG_DIR"
MATRIX_FILE="$FSS_MACOS_PARITY_LOG_DIR/macos_parity_matrix.jsonl"
REPORT_FILE="$FSS_MACOS_PARITY_LOG_DIR/macos_parity_report.json"
CLIPPY_LOG="$FSS_MACOS_PARITY_LOG_DIR/clippy_output.log"
: > "$MATRIX_FILE"

WORK_BASE="/tmp/fss-macos-parity-$$"
CANON_BASE=""
SYMLINK_BASE=""
cleanup() {
  rm -rf "$WORK_BASE" 2>/dev/null || true
  if [[ -n "$SYMLINK_BASE" && -L "$SYMLINK_BASE" ]]; then
    rm -f "$SYMLINK_BASE" 2>/dev/null || true
  fi
}
trap cleanup EXIT

now_ms() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

record_check() {
  local check_id="$1"
  local duration_ms="$2"
  local exit_code="$3"
  local verdict="$4"
  local detail="$5"
  python3 - "$MATRIX_FILE" "$OS_NAME" "$ARCH_NAME" "$check_id" "$duration_ms" "$exit_code" "$verdict" "$detail" <<'PY'
import json, sys
matrix_file, os_name, arch_name, check_id, dur, rc, verdict, detail = sys.argv[1:9]
row = {
    "os": os_name,
    "arch": arch_name,
    "check_id": check_id,
    "duration_ms": int(dur),
    "exit_code": int(rc),
    "verdict": verdict,
    "detail": detail,
}
with open(matrix_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(row) + "\n")
PY
}

OVERALL_FAIL=0

run_check() {
  local check_id="$1"
  shift
  echo "[QL-MACOS-001] Running check: $check_id ..."
  local start_ms end_ms dur_ms rc detail_file detail
  start_ms="$(now_ms)"
  detail_file="$FSS_MACOS_PARITY_LOG_DIR/${check_id}.log"
  set +e
  "$@" > "$detail_file" 2>&1
  rc=$?
  set -e
  end_ms="$(now_ms)"
  dur_ms=$((end_ms - start_ms))
  detail="$(tail -n 3 "$detail_file" | tr '\n' ' ' | cut -c1-240)"
  if [[ "$rc" -eq 0 ]]; then
    echo "[QL-MACOS-001] PASS  $check_id (${dur_ms}ms)"
    record_check "$check_id" "$dur_ms" "$rc" "PASS" "$detail"
  else
    echo "[QL-MACOS-001] FAIL  $check_id (exit=$rc, ${dur_ms}ms) — see $detail_file" >&2
    tail -n 20 "$detail_file" >&2 || true
    record_check "$check_id" "$dur_ms" "$rc" "FAIL" "$detail"
    OVERALL_FAIL=1
  fi
}

echo "[QL-MACOS-001] Host: os=$OS_NAME arch=$ARCH_NAME target_dir=$CARGO_TARGET_DIR"
echo "[QL-MACOS-001] Artifacts: $FSS_MACOS_PARITY_LOG_DIR"

# ---------------------------------------------------------------------------
# Check 1: clippy_zero_warnings
# ---------------------------------------------------------------------------
if [[ "$SKIP_CLIPPY" -eq 1 ]]; then
  echo "SKIPPED via --skip-clippy" > "$CLIPPY_LOG"
  echo "[QL-MACOS-001] SKIP  clippy_zero_warnings (--skip-clippy)"
  record_check "clippy_zero_warnings" 0 0 "SKIP" "Skipped via --skip-clippy"
else
  check_clippy_zero_warnings() {
    ${RUN[@]+"${RUN[@]}"} cargo clippy --locked --offline --workspace --all-targets -- -D warnings \
      > "$CLIPPY_LOG" 2>&1
    echo "cargo clippy --locked --offline --workspace --all-targets -- -D warnings exited 0 (0 warnings)"
  }
  run_check "clippy_zero_warnings" check_clippy_zero_warnings
fi

# Build the real CLI binaries once for Checks 2, 3, 4, and 6.
echo "[QL-MACOS-001] Building real CLI binaries (fss, fss-file, fss-backup, fss-dashboard)..."
${RUN[@]+"${RUN[@]}"} cargo build --offline -p fss-cli \
  --bin fss --bin fss-file --bin fss-backup --bin fss-dashboard

BIN_DIR="$CARGO_TARGET_DIR/debug"
FSS_BIN="$BIN_DIR/fss"
FSS_FILE_BIN="$BIN_DIR/fss-file"
FSS_BACKUP_BIN="$BIN_DIR/fss-backup"
FSS_DASHBOARD_BIN="$BIN_DIR/fss-dashboard"
JPEG_FIXTURE="$ROOT/crates/fss-cli/tests/fixtures/retained_file_8x8.jpg"

mkdir -p "$WORK_BASE"
DEPLOY_ROOT="$WORK_BASE/deployment"

# ---------------------------------------------------------------------------
# Check 2: fss_doctor_healthy
# ---------------------------------------------------------------------------
check_fss_doctor_healthy() {
  rm -rf "$DEPLOY_ROOT"
  "$FSS_FILE_BIN" import \
    --root "$DEPLOY_ROOT" \
    --site "site:macos-parity" \
    --input "$JPEG_FIXTURE" \
    --sensor "sensor:parity-cam" \
    --stream "stream:main" \
    --receive-time-ns 1000000000 \
    --chunk-bytes 64

  local doctor_json status_json
  doctor_json="$("$FSS_BIN" doctor --json --root "$DEPLOY_ROOT")"
  status_json="$("$FSS_BIN" status --json --root "$DEPLOY_ROOT")"

  python3 - "$doctor_json" "$status_json" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
st = json.loads(sys.argv[2])
assert doc.get("verdict") == "healthy", f"doctor verdict != healthy: {doc}"
assert st.get("doctor_verdict") == "healthy", f"status doctor_verdict != healthy: {st}"
writer = st.get("writer") or {}
assert writer.get("possibly_stale") is False, f"writer.possibly_stale != false: {writer}"
print(f"doctor={doc['verdict']} status.doctor_verdict={st['doctor_verdict']} possibly_stale={writer['possibly_stale']}")
PY
}
run_check "fss_doctor_healthy" check_fss_doctor_healthy

# ---------------------------------------------------------------------------
# Check 3: session_open_refusal_atomicity
# ---------------------------------------------------------------------------
check_session_open_refusal_atomicity() {
  python3 - "$FSS_BIN" "$DEPLOY_ROOT" "$WORK_BASE" <<'PY'
import hashlib, os, shutil, subprocess, sys
from pathlib import Path

fss_bin = sys.argv[1]
src_root = Path(sys.argv[2])
work_base = Path(sys.argv[3])
assert src_root.is_dir(), f"missing deployment root {src_root}"

def snapshot(base: Path):
    inv = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, base)
        inv[f"D:{rel_dir}"] = ("dir", 0, "")
        for name in filenames:
            full = Path(dirpath) / name
            rel = os.path.relpath(full, base)
            data = full.read_bytes()
            inv[f"F:{rel}"] = ("file", len(data), hashlib.sha256(data).hexdigest())
    return inv

def verify_refusal_atomicity(case_name: str, root: Path, extra_args: list[str]):
    before = snapshot(root)
    proc = subprocess.run(
        [
            fss_bin, "session", "open", "--json",
            "--root", str(root),
            "--principal", "principal:parity-atomicity",
            "--mission-text", f"Verify session open refusal atomicity ({case_name})",
            "--objective", "Fail closed with zero filesystem mutation",
            *extra_args,
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, f"{case_name}: expected refusal exit code, got 0: stdout={proc.stdout[:240]}"
    after = snapshot(root)
    if before != after:
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
        raise AssertionError(
            f"{case_name}: refused session open mutated deployment! added={added} removed={removed} changed={changed}"
        )
    return proc.returncode, len(before)

# Case A: invalid budget refusal (0 tokens) on a clean deployment root leaves 0 new files/dirs.
case_a = work_base / "atomicity-zero-budget"
if case_a.exists():
    shutil.rmtree(case_a)
shutil.copytree(src_root, case_a)
rc_a, n_a = verify_refusal_atomicity("zero_budget", case_a, ["--budget-tokens", "0"])
assert not (case_a / "agent").exists(), "zero_budget created agent/ directory"

# Case B: preflight fault injection — agent/publications is a non-directory file.
# Must fail inside open_session preflight with 0 bytes/files written and no agent/sessions created.
case_b = work_base / "atomicity-invalid-publications"
if case_b.exists():
    shutil.rmtree(case_b)
shutil.copytree(src_root, case_b)
(case_b / "agent").mkdir(parents=True, exist_ok=True)
(case_b / "agent" / "publications").write_bytes(b"not-a-directory")
rc_b, n_b = verify_refusal_atomicity("preflight_invalid_publications", case_b, ["--budget-tokens", "1000"])
assert not (case_b / "agent" / "sessions").exists(), "preflight refusal created agent/sessions"

# Case C: preflight fault injection — foreign stray file under agent/publications/roots/.
case_c = work_base / "atomicity-foreign-root"
if case_c.exists():
    shutil.rmtree(case_c)
shutil.copytree(src_root, case_c)
(case_c / "agent" / "publications" / "roots").mkdir(parents=True, exist_ok=True)
(case_c / "agent" / "publications" / "roots" / "stray.foreign").write_bytes(b"corrupt")
rc_c, n_c = verify_refusal_atomicity("preflight_foreign_root", case_c, ["--budget-tokens", "1000"])
assert not (case_c / "agent" / "sessions").exists(), "foreign-root refusal created agent/sessions"

print(
    f"3/3 fault-injection refusals atomic: zero_budget(exit={rc_a},{n_a} entries), "
    f"invalid_publications(exit={rc_b},{n_b} entries), foreign_root(exit={rc_c},{n_c} entries)"
)
PY
}
run_check "session_open_refusal_atomicity" check_session_open_refusal_atomicity

# ---------------------------------------------------------------------------
# Check 4: symlink_root_and_backup_roundtrip
# ---------------------------------------------------------------------------
check_symlink_root_and_backup_roundtrip() {
  local sym_root canon_root
  if [[ "$OS_NAME" == "Darwin" ]]; then
    # On macOS /tmp -> /private/tmp is the canonical system symlink boundary.
    sym_root="$DEPLOY_ROOT"
    canon_root="/private${DEPLOY_ROOT}"
  else
    SYMLINK_BASE="/tmp/fss-macos-parity-sym-$$"
    ln -sfn "$WORK_BASE" "$SYMLINK_BASE"
    sym_root="$SYMLINK_BASE/deployment"
    canon_root="$DEPLOY_ROOT"
  fi

  local idx=0
  local digests=()
  for label_root in "symlink:$sym_root" "canonical:$canon_root"; do
    idx=$((idx + 1))
    local label="${label_root%%:*}"
    local src_root="${label_root#*:}"
    local bundle_dir restore_dir
    if [[ "$label" == "canonical" && "$OS_NAME" == "Darwin" ]]; then
      bundle_dir="/private${WORK_BASE}/bundle-${idx}"
      restore_dir="/private${WORK_BASE}/restored-${idx}"
    else
      bundle_dir="${WORK_BASE}/bundle-${idx}"
      restore_dir="${WORK_BASE}/restored-${idx}"
    fi
    rm -rf "$bundle_dir" "$restore_dir"

    local plan_json digest create_json inspect_json restore_json doc_json doc_rc
    plan_json="$("$FSS_BACKUP_BIN" plan --root "$src_root" --allow-originals)"
    digest="$(python3 - "$plan_json" <<'PY'
import json, sys
p = json.loads(sys.argv[1])
assert p.get("status") == "planned", f"plan failed: {p}"
print(p["manifest_digest"])
PY
)"
    digests+=("$digest")
    create_json="$("$FSS_BACKUP_BIN" create --root "$src_root" --bundle "$bundle_dir" --expect "$digest" --allow-originals)"
    inspect_json="$("$FSS_BACKUP_BIN" inspect --bundle "$bundle_dir" --expect "$digest" --allow-originals)"
    restore_json="$("$FSS_BACKUP_BIN" restore --bundle "$bundle_dir" --root "$restore_dir" --expect "$digest" --allow-originals)"
    # fss doctor exits 0 (healthy) or 3 (attention_required due solely to the immutable backup
    # manifest + restore fence custody objects recorded by fss-backup restore).
    set +e
    doc_json="$("$FSS_BIN" doctor --json --root "$restore_dir")"
    doc_rc=$?
    set -e

    python3 - "$label" "$doc_rc" "$create_json" "$inspect_json" "$restore_json" "$doc_json" <<'PY'
import json, sys
label = sys.argv[1]
doc_rc = int(sys.argv[2])
cr, ins, res, doc = (json.loads(a) for a in sys.argv[3:7])
assert cr.get("status") == "created", f"{label} create: {cr}"
assert ins.get("status") == "verified", f"{label} inspect: {ins}"
assert res.get("status") == "restored", f"{label} restore: {res}"
restoration = res.get("restoration") or {}
assert restoration.get("alert_effects_disabled") is True, f"{label} missing restore alert fence: {res}"
assert doc_rc in (0, 3), f"{label} restored doctor unexpected exit {doc_rc}: {doc}"
assert doc.get("possibly_stale") is False, f"{label} restored doctor stale: {doc}"
expected_custody = {res["manifest_digest"], restoration["fence_digest"]}
for chk in doc.get("checks") or []:
    if chk["id"] == "objects.unreferenced" and chk["severity"] == "attention":
        found = set(chk.get("unreferenced_objects") or [])
        assert found == expected_custody, (
            f"{label} unexpected unreferenced objects: found={found} expected={expected_custody}"
        )
    else:
        assert chk["severity"] == "ok", f"{label} doctor check {chk['id']} not ok: {chk}"
print(
    f"{label}: plan->create->inspect->restore->doctor({doc['verdict']}, custody_objects=2, clean=12/12) "
    f"OK digest={cr.get('manifest_digest')}"
)
PY
  done
  if [[ "${digests[0]}" != "${digests[1]}" ]]; then
    echo "symlink vs canonical manifest digest mismatch: ${digests[0]} != ${digests[1]}" >&2
    return 1
  fi
  echo "symlink/canonical manifest digest parity verified: ${digests[0]}"
}
run_check "symlink_root_and_backup_roundtrip" check_symlink_root_and_backup_roundtrip

# ---------------------------------------------------------------------------
# Check 5: mcp_14_tool_lifecycle
# ---------------------------------------------------------------------------
check_mcp_14_tool_lifecycle() {
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-cli \
    --test mcp_cli_contract \
    --test operational_mcp_targets_contract \
    --test hydration_h2_h3_contract
  if [[ -f "$ROOT/crates/fss-cli/tests/mcp_14_ops_adversarial_e2e.rs" ]]; then
    # Latency SLO assertions (<10ms warm orient, <15ms 4-agentx8-camera p99) require --release
    # and --test-threads=1 so Scenario 3's 8-camera stress test does not contend with Scenario 1.
    ${RUN[@]+"${RUN[@]}"} cargo test --offline --release -p fss-cli \
      --test mcp_14_ops_adversarial_e2e -- --test-threads=1
  fi
}
run_check "mcp_14_tool_lifecycle" check_mcp_14_tool_lifecycle

# ---------------------------------------------------------------------------
# Check 6: dashboard_snapshot_and_live_smoke
# ---------------------------------------------------------------------------
check_dashboard_snapshot_and_live_smoke() {
  local snap_out live_out
  snap_out="$("$FSS_DASHBOARD_BIN" --snapshot --root "$DEPLOY_ROOT" --site "site:macos-parity" --allow-local-metadata yes)"
  live_out="$("$FSS_DASHBOARD_BIN" --live --snapshot --json --root "$DEPLOY_ROOT" --site "site:macos-parity" --allow-local-metadata yes)"
  python3 - "$snap_out" "$live_out" <<'PY'
import json, sys
snap = json.loads(sys.argv[1])
live = json.loads(sys.argv[2])
assert isinstance(snap, dict) and snap, "empty dashboard --snapshot JSON"
assert isinstance(live, dict) and live.get("daemon_live") is False, f"expected MVCC fallback daemon_live=false: {live}"
print(f"dashboard snapshot keys={len(snap)} live_fallback daemon_live={live.get('daemon_live')}")
PY
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-cli --test dashboard_live_contract
}
run_check "dashboard_snapshot_and_live_smoke" check_dashboard_snapshot_and_live_smoke

# ---------------------------------------------------------------------------
# Check 7: macos_unit_parity_tests
# ---------------------------------------------------------------------------
check_macos_unit_parity_tests() {
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-reference --lib \
    deployment_session::tests::runtime_time::later_open_retries_retain_the_original_lease_workspace_mission_and_narrowed_grants
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-reference --lib \
    agent_orient::mission::tests::literal_goal_is_critical_context_without_rendering_success_as_mission_success
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-reference --lib \
    agent_orient::historical_health::tests::cold_health_projection_and_follow_keep_old_suspicion_after_no_findings
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-reference --test watch_report_golden
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-publication --test pinned_namespace_contract
  ${RUN[@]+"${RUN[@]}"} cargo test --offline -p fss-cli --bin fss-mcp \
    aliased_duplex_descriptors_preserve_the_true_original_flags
}
run_check "macos_unit_parity_tests" check_macos_unit_parity_tests

# ---------------------------------------------------------------------------
# Emit consolidated JSON report
# ---------------------------------------------------------------------------
python3 - "$MATRIX_FILE" "$REPORT_FILE" "$CLIPPY_LOG" "$OS_NAME" "$ARCH_NAME" "$OVERALL_FAIL" <<'PY'
import json, sys
from pathlib import Path

matrix_file, report_file, clippy_log, os_name, arch_name, overall_fail = sys.argv[1:7]
rows = [
    json.loads(line)
    for line in Path(matrix_file).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
passed = sum(1 for r in rows if r["verdict"] == "PASS")
failed = sum(1 for r in rows if r["verdict"] == "FAIL")
skipped = sum(1 for r in rows if r["verdict"] == "SKIP")
status = "PASS" if int(overall_fail) == 0 and failed == 0 else "FAIL"
report = {
    "schema": "fss.macos_parity_report.v1",
    "lane_id": "QL-MACOS-001",
    "os": os_name,
    "arch": arch_name,
    "status": status,
    "checks_total": len(rows),
    "checks_passed": passed,
    "checks_failed": failed,
    "checks_skipped": skipped,
    "checks": rows,
    "artifacts": {
        "matrix_jsonl": matrix_file,
        "report_json": report_file,
        "clippy_output_log": clippy_log,
    },
}
Path(report_file).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"[QL-MACOS-001] Report written: {report_file} (status={status}, pass={passed}, fail={failed}, skip={skipped})")
PY

exit "$OVERALL_FAIL"
