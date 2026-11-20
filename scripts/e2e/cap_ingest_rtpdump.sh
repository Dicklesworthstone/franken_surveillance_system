#!/usr/bin/env bash
# Recorded RTP file import, reopened ledger capsules and transport fault accounting.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_ingest_rtpdump.sh"
e2e_init "ingest_rtpdump" "fss-2h5zq.28" "$@"
export FSS_EXPECTED_ROSTER="clean,loss,reorder,duplicate,ssrc_reset,truncated_last_record,large_gap"
e2e_cargo_test "fss-reference" "rtpdump_fixture_contract"
export FSS_EXPECTED_ROSTER="truncated_record,larger_plen,zero_plen,fragment_gap,header_privacy"
if [[ "$_E2E_ONLY" == "header_privacy_log" || "$_E2E_ONLY" == "header_privacy_log_exit" ]]; then
    # The retained-log check requires a real import of the privacy fixture in this run.
    _E2E_ONLY=rtpdump_ingest_contract e2e_cargo_test "fss-reference" "rtpdump_ingest_contract"
else
    e2e_cargo_test "fss-reference" "rtpdump_ingest_contract"
fi

check_header_privacy() {
    python3 - "$_E2E_LOG_FILE" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if "192.0.2.89" in raw:
    sys.exit("recording header endpoint appeared in the retained log")
if not any(row["step"].endswith("header_privacy") and row["verdict"] == "pass"
           for row in map(json.loads, raw.splitlines())):
    sys.exit("the header privacy case did not run")
PY
}
e2e_step header_privacy_log -- check_header_privacy
e2e_expect_exit header_privacy_log 0
e2e_summary
