#!/usr/bin/env bash
# CAP- EXEC activity package (fss-2h5zq.50): package root, verify verdict, tamper and license
# refusals, generation refusal, hand-computed score and preprocessing goldens (CAPLOG per case).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_exec_activity_package.sh"
e2e_init "exec_activity_package" "fss-2h5zq.50" "$@"
# Every record must report; a missing record is a failure, not a silent skip.
export FSS_EXPECTED_ROSTER="package_rebuilt_bit_exact,committed_package_verified,archive_tamper_refused,repinned_tamper_refused,license_denial_refused,other_generation_refused,cancelled_load_refused,preprocess_goldens,generation_isolation,score_golden_32x32_identical,score_golden_32x32_all_white,score_golden_32x32_top_half,score_golden_64x48_top_half,score_golden_16x16_one_pixel,score_golden_33x17_one_pixel,fixture_score_matches_f64"
e2e_cargo_test "fss-reference" "activity_model_contract"
e2e_summary
