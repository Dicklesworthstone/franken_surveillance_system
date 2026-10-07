#!/usr/bin/env bash
# CAP- EXEC activity package (fss-2h5zq.50): package root, verify verdict, tamper and license
# refusals, generation refusal, hand-computed score and preprocessing goldens (CAPLOG per case).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_exec_activity_package.sh"
e2e_init "exec_activity_package" "fss-2h5zq.50" "$@"
e2e_cargo_test "fss-reference" "activity_model_contract"
e2e_summary
