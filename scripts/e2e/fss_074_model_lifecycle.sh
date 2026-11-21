#!/usr/bin/env bash
# FSS-074 (`fss-x4a.14.5`) E2E verification: model qualification, shadow evaluation,
# two-phase authorized activation, atomic reader snapshots (FORMAL-007), rollback,
# quarantine, revocation/anti-rollback, and canonical journal crash-replay parity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_074_model_lifecycle.sh"
e2e_init "fss_074_model_lifecycle" "fss-x4a.14.5" "$@"
e2e_cargo_test "fss-model-ir" "model_lifecycle_contract"
e2e_summary
