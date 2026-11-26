#!/usr/bin/env bash
# QL-CUSTODY-001 — Reusable local qualification lane: release custody (`fss-x4a.29.21`).
#
# Exact scope (`docs/LOCAL_QUALIFICATION_WITH_DSR.md`):
#   1. source_and_manifest_roots       — policy constitution, repository manifest audit, sibling closure
#   2. exact_assets_and_checksums      — deterministic archive, SHA256SUMS, exact asset enumeration
#   3. sbom_and_license_agreement      — SPDX SBOM == license inventory == Cargo.lock == receipt (FSS-190)
#   4. separated_signing_authority     — builder != signer Ed25519 signing authority refusal (FSS-191)
#   5. root_last_upload_download_verify — root-last publication, download-verify, lost-ACK reconcile (FSS-192)
#                                        and sealed-offline GitHub-unavailable drill (FSS-194)
#
# Never contacts external providers or networks (`CARGO_NET_OFFLINE=true`).
# Never upgrades a skipped, unavailable, or failed check into a pass.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE_ID="QL-CUSTODY-001"
LANE_NAME="custody"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/lanes/custody.sh [--list] [--receipt-dir DIR]
                                [--verify-receipt RECEIPT_JSON [--allow-static-only]]
                                [--only-static] [--dry-run-missing-prereq]
USAGE
}

MODE="run"
RECEIPT_DIR="${FSS_CUSTODY_RECEIPT_DIR:-}"
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
    *) printf 'QL-CUSTODY-001: unknown argument: %s\n' "$1" >&2; usage; exit 4 ;;
  esac
done

declare -a STEP_IDS=(
  "cus-01-policy-constitution"
  "cus-02-manifest-audit"
  "cus-03-sibling-closure"
  "cus-04-sbom-license-crosscheck"
  "cus-05-separated-signing-authority"
  "cus-06-root-last-upload-verify"
  "cus-07-exact-assets-and-checksums"
  "cus-08-offline-github-unavailable-drill"
)

declare -a STEP_PILLARS=(
  "source_and_manifest_roots"
  "source_and_manifest_roots"
  "source_and_manifest_roots"
  "sbom_and_license_agreement"
  "separated_signing_authority"
  "root_last_upload_download_verify"
  "exact_assets_and_checksums"
  "root_last_upload_download_verify"
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
if receipt_path.is_symlink() or not receipt_path.is_file():
    print(f"[FAIL] QL-CUSTODY-001 verifier: receipt missing or symlinked: {receipt_path}", file=sys.stderr)
    sys.exit(2)

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[FAIL] QL-CUSTODY-001 verifier: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if receipt.get("schema") != "fss.release_qualification_receipt.v1":
    print(f"[FAIL] unexpected schema: {receipt.get('schema')}", file=sys.stderr)
    sys.exit(2)
if receipt.get("laneId") != "QL-CUSTODY-001":
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
steps_jsonl = run_dir / "custody-steps.jsonl"
if steps_jsonl.is_symlink() or not steps_jsonl.is_file():
    print(f"[FAIL] missing or symlinked structured step log: {steps_jsonl}", file=sys.stderr)
    sys.exit(2)

SECRET_MARKERS = ("BEGIN PRIVATE KEY", "AKIA", "rtsp-pass-gen1", "password=", "Authorization: Bearer ")
FULL_STEP_IDS = [
    "cus-01-policy-constitution",
    "cus-02-manifest-audit",
    "cus-03-sibling-closure",
    "cus-04-sbom-license-crosscheck",
    "cus-05-separated-signing-authority",
    "cus-06-root-last-upload-verify",
    "cus-07-exact-assets-and-checksums",
    "cus-08-offline-github-unavailable-drill",
]
STATIC_STEP_IDS = FULL_STEP_IDS[:6]
REQUIRED_FULL_PILLARS = {
    "source_and_manifest_roots",
    "exact_assets_and_checksums",
    "sbom_and_license_agreement",
    "separated_signing_authority",
    "root_last_upload_download_verify",
}

step_rows = []
for idx, raw_line in enumerate(steps_jsonl.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw_line.strip():
        continue
    row = json.loads(raw_line)
    if row.get("laneId") != "QL-CUSTODY-001":
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
        print(f"[FAIL] incomplete QL-CUSTODY-001 receipt: expected all {len(FULL_STEP_IDS)} steps, got {observed_ids}", file=sys.stderr)
        sys.exit(2)
    observed_pillars = {row.get("pillar") for row in step_rows}
    if observed_pillars != REQUIRED_FULL_PILLARS:
        print(f"[FAIL] missing required custody pillars: {REQUIRED_FULL_PILLARS - observed_pillars}", file=sys.stderr)
        sys.exit(2)

for idx, (cmd, row) in enumerate(zip(commands, step_rows), start=1):
    if cmd.get("argv") != row.get("argv"):
        print(f"[FAIL] command {idx} argv disagrees with custody-steps.jsonl", file=sys.stderr)
        sys.exit(2)
    if cmd.get("status") != "passed":
        print(f"[FAIL] command {idx} non-passing status: {cmd.get('status')}", file=sys.stderr)
        sys.exit(1)
    if cmd.get("outputDigest") != row.get("outputDigest"):
        print(f"[FAIL] command {idx} outputDigest disagrees with custody-steps.jsonl", file=sys.stderr)
        sys.exit(2)

mode_label = "static-only" if observed_ids == STATIC_STEP_IDS else "full-5-pillar"
print(f"[PASS] QL-CUSTODY-001 standalone verifier ({mode_label}): {len(step_rows)} steps, 0 secret leaks, all digests verified")
PY
fi

cd "$ROOT"

if ((SIMULATE_MISSING_PREREQ)); then
  printf '{"laneId":"%s","status":"unavailable_prerequisite","reason":"simulated_missing_prerequisite","guidance":"install_python3_and_pinned_toolchain_and_retry"}\n' "$LANE_ID" >&2
  exit 5
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf '{"laneId":"%s","status":"unavailable_prerequisite","reason":"python3_unavailable","guidance":"provision_python3_3_11_plus"}\n' "$LANE_ID" >&2
  exit 5
fi

TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
started_ns="$(python3 -c 'import time; print(time.time_ns())')"
if [[ -z "$RECEIPT_DIR" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --unique "$ROOT/qualification-artifacts/local/${stamp}-custody")"
else
  RECEIPT_DIR="$(python3 "$ROOT/scripts/qualification_receipt.py" prepare-run-dir --exact "$RECEIPT_DIR")"
fi

records="$RECEIPT_DIR/commands.jsonl"
steps_log="$RECEIPT_DIR/custody-steps.jsonl"
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
        "guidance": "none" if status == "passed" else "inspect_step_log_and_repair_release_custody",
    }, separators=(",", ":")) + "\n")
    fh.flush(); os.fsync(fh.fileno())
PY

  if ((rc != 0)); then
    printf '[FAIL] %s (%s/%s) — see %s\n' "$LANE_ID" "$pillar" "$step_id" "$log_path" >&2
    return 0
  fi
  printf '[PASS] %s (%s/%s) %s (%dms)\n' "$LANE_ID" "$pillar" "$step_id" "$digest" "$dur_ms" >&2
}

# Fast custody verification legs (source roots, SBOM agreement, signing authority, root-last publish/verify).
run_step "cus-01-policy-constitution" "source_and_manifest_roots" python3 scripts/check-policy.py --skip-manifest
run_step "cus-02-manifest-audit" "source_and_manifest_roots" python3 scripts/manifest_audit.py
run_step "cus-03-sibling-closure" "source_and_manifest_roots" python3 scripts/sibling_closure.py "$ROOT"
run_step "cus-04-sbom-license-crosscheck" "sbom_and_license_agreement" python3 -m unittest tests/test_sbom_crosscheck.py
run_step "cus-05-separated-signing-authority" "separated_signing_authority" python3 -m unittest tests/test_signing_authority.py
run_step "cus-06-root-last-upload-verify" "root_last_upload_download_verify" python3 -m unittest tests/test_release_publication.py

if ((ONLY_STATIC == 0)); then
  run_step "cus-07-exact-assets-and-checksums" "exact_assets_and_checksums" \
    env RCH_SHIM_LOCAL_IDE=1 python3 -m unittest tests/test_release_artifacts.py
  run_step "cus-08-offline-github-unavailable-drill" "root_last_upload_download_verify" \
    python3 scripts/offline_github_unavailable_drill.py
fi

finished_ns="$(python3 -c 'import time; print(time.time_ns())')"
source_commit="git:$(git rev-parse HEAD 2>/dev/null || printf unknown00000000)"
source_tree="git-tree:$(git rev-parse HEAD^{tree} 2>/dev/null || printf unknown00000000)"
sibling_digest="${FSS_DSR_SIBLING_CLOSURE_DIGEST:-$(python3 "$ROOT/scripts/sibling_closure.py" "$ROOT")}"
host_digest="sha256:$(python3 -c 'import hashlib, os, platform; print(hashlib.sha256("|".join([platform.node(), platform.platform(), platform.machine(), os.environ.get("FSS_DSR_HOST_ID", "")]).encode()).hexdigest())')"
target="${FSS_TARGET_TRIPLE:-$(uname -s)-$(uname -m)}"
manifest_root="$(python3 scripts/manifest_audit.py 2>/dev/null | sed -n 's/^effectiveRoot=//p' | head -1 || true)"
[[ -n "$manifest_root" ]] || manifest_root="unavailable"

receipt_path="$RECEIPT_DIR/custody-receipt.json"
receipt_status="$(python3 "$ROOT/scripts/qualification_receipt.py" finalize \
  --output "$receipt_path" --records "$records" --lane "$LANE_NAME" \
  --source-commit "$source_commit" --source-tree "$source_tree" \
  --sibling-digest "$sibling_digest" --host-digest "$host_digest" \
  --toolchain "${TOOLCHAIN:-unavailable}" --target "$target" \
  --started-ns "$started_ns" --finished-ns "$finished_ns" \
  --status "$overall_status" --manifest-root "$manifest_root" \
  --cargo-lock "$ROOT/Cargo.lock")"

printf 'QL-CUSTODY-001 receipt: %s (status=%s)\n' "$receipt_path" "$receipt_status" >&2
[[ "$receipt_status" == "passed" ]]
