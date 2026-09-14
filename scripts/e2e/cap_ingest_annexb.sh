#!/usr/bin/env bash
# scripts/e2e/cap_ingest_annexb.sh
# End-to-end runner for CAP- INGEST Annex-B stream splitter (fss-2h5zq.20) on the shared harness
# scripts/e2e/lib.sh (fss-2h5zq.1). It runs one cargo test target, annexb_split_contract, remotely
# through rch; every CAPLOG record it prints becomes one step of
# ${FSS_E2E_LOG_DIR:-target/e2e-logs}/ingest_annexb/run_NNNN.log.
#
# After ingestion, a roster/comparison gate (fss-qwp8y) fails the run when any of the 19 required
# roster steps is missing or a pass record's expected != observed, so the B8 contract checks can
# never silently vanish. Without lib.sh the script fails closed: there is no second, divergent
# harness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/lib.sh" ]]; then
    echo "Error: ${SCRIPT_DIR}/lib.sh (the fss-2h5zq.1 harness) is required; refusing to run without it" >&2
    exit 1
fi

# The 19-step roster every full annexb_split_contract run must execute (override for a scoped run).
_ANNEXB_ROSTER="${FSS_EXPECTED_ROSTER:-manifest_clean_h264,synthetic_standard,synthetic_multi_slice,padding_and_leading_zeros,no_aud_grouping,empty_and_no_start_code,zero_length_and_truncated,forbidden_zero_bit,leading_garbage_limits,emulation_prevention,slice_header_syntax,undecodable_flag,unsupported_extensions,limits_boundaries,cooperative_cancellation,mutant_kill_table,mutation_gauntlet_10k,loop_and_mid_push_limits,validation_ceiling_bypass}"

# Reads the run log written so far and fails (exit 1) if any roster step is missing or any pass
# record has expected != observed. Runs as an e2e_step so its verdict lands in the summary.
_annexb_roster_gate() {
    python3 - "$_E2E_LOG_FILE" "$_ANNEXB_ROSTER" <<'PY'
import json
import sys

log_path, roster_csv = sys.argv[1], sys.argv[2]
roster = [s.strip() for s in roster_csv.split(",") if s.strip()]
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
            exp = rec.get("expected")
            obs = rec.get("observed")
            if exp is not None and obs is not None and exp != obs:
                problems.append(f"{step}: pass record with expected != observed")

# No annexb records at all means the target did not run under this invocation (e.g. a scoped
# --only that excluded it); there is nothing to gate.
if not seen:
    sys.exit(0)

missing = [s for s in roster if s not in seen]
if missing:
    problems.append("missing roster steps: " + ", ".join(missing))

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
e2e_step "annexb_roster_gate" -- _annexb_roster_gate
e2e_summary
