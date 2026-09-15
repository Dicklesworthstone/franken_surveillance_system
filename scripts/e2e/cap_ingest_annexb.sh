#!/usr/bin/env bash
# scripts/e2e/cap_ingest_annexb.sh
# End-to-end runner for CAP- INGEST Annex-B stream splitter (fss-2h5zq.20) on the shared harness
# scripts/e2e/lib.sh (fss-2h5zq.1). It runs one cargo test target, annexb_split_contract, remotely
# through rch; every CAPLOG record it prints becomes one step of
# ${FSS_E2E_LOG_DIR:-target/e2e-logs}/ingest_annexb/run_NNNN.log.
#
# After ingestion, a roster/comparison gate (fss-qwp8y) fails the run when any of the 19 required
# roster steps is missing or a pass record's expected != observed (type-strict, observed required),
# so the B8 contract checks can never silently vanish. The gate follows the target: it runs whenever
# the target runs, fails closed when selected alone, and its repro is --only annexb_split_contract. Without lib.sh the script fails closed: there is no second, divergent
# harness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/lib.sh" ]]; then
    echo "Error: ${SCRIPT_DIR}/lib.sh (the fss-2h5zq.1 harness) is required; refusing to run without it" >&2
    exit 1
fi

# The 19-step roster every full annexb_split_contract run must execute (override for a scoped run).
_ANNEXB_ROSTER="${FSS_EXPECTED_ROSTER:-manifest_clean_h264,synthetic_standard,synthetic_multi_slice,padding_and_leading_zeros,no_aud_grouping,empty_and_no_start_code,zero_length_and_truncated,forbidden_zero_bit,leading_garbage_limits,emulation_prevention,slice_header_syntax,undecodable_flag,unsupported_extensions,limits_boundaries,cooperative_cancellation,mutant_kill_table,mutation_gauntlet_10k,loop_and_mid_push_limits,validation_ceiling_bypass}"

# Reads the run log written so far and fails (exit 1) when:
#   - there is no annexb_split_contract record at all (the gate was selected alone: fail closed);
#   - any roster step is missing;
#   - a pass record lacks expected or observed, or its expected != observed, compared TYPE-STRICTLY
#     (1, 1.0 and true all differ; JSON objects compare key by key, arrays element by element).
# It runs as `e2e_step --selector annexb_split_contract`, so it runs whenever the target runs (also
# under --only annexb_split_contract) and a gate failure reruns --only annexb_split_contract.
_annexb_roster_gate() {
    python3 - "$_E2E_LOG_FILE" "$_ANNEXB_ROSTER" <<'PY'
import json
import sys

log_path, roster_csv = sys.argv[1], sys.argv[2]
roster = [s.strip() for s in roster_csv.split(",") if s.strip()]


def strict_eq(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_eq(x, y) for x, y in zip(a, b))
    return a == b


seen = set()
problems = []
with open(log_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        step = rec.get("step")
        if step in ("env", "summary"):
            continue
        seen.add(step)
        if rec.get("verdict") == "pass":
            missing = [k for k in ("expected", "observed") if rec.get(k) is None]
            if missing:
                problems.append(f"pass record of step {step!r} without {' and '.join(missing)}")
            elif not strict_eq(rec["expected"], rec["observed"]):
                problems.append(f"pass record of step {step!r} has expected != observed")

if not seen:
    problems.append("no annexb_split_contract record in this run: the gate audits the target's "
                    "records and cannot run alone (rerun with --only annexb_split_contract)")
else:
    missing_steps = [s for s in roster if s not in seen]
    if missing_steps:
        problems.append("missing roster steps: " + ", ".join(missing_steps))

if problems:
    for p in problems:
        sys.stderr.write("annexb roster/comparison violation: " + p + "\n")
    sys.exit(1)
sys.exit(0)
PY
}

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
e2e_init "ingest_annexb" "fss-2h5zq.20" "$@"
e2e_cargo_test "fss-reference" "annexb_split_contract"
e2e_step --selector annexb_split_contract "annexb_roster_gate" -- _annexb_roster_gate
e2e_summary
