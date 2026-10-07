#!/usr/bin/env bash
# CAP- EXEC invocation receipt (fss-2h5zq.48): one emitted receipt per outcome plus the
# package-backed activity receipt, pinned to the schema-validated fixtures, determinism and the
# independently recomputed operator trace chain. The schema verdicts on the same bytes come from
# tests/test_json_instance_validate.py (policy lane).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_exec_receipt.sh"
e2e_init "exec_receipt" "fss-2h5zq.48" "$@"
# Every record must report; a missing record is a failure, not a silent skip.
export FSS_EXPECTED_ROSTER="receipt_ok,receipt_error,receipt_budget_exhausted,receipt_cancelled,receipt_activity_package,receipt_activity_binding"
e2e_cargo_test "fss-reference" "model_receipt_contract"
e2e_summary
