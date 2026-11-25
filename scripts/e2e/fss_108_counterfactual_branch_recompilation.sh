#!/usr/bin/env bash
# E2E proof driver for FSS-108 (fss-x4a.9.15): Counterfactual branch overlay & live-intent recompilation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "counterfactual_overlay_isolation_diff_and_live_head_recompilation_commit"
    "counterfactual_refuses_effect_authority_laundering_cancel_and_hostile_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_108_counterfactual_branch_recompilation"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-ledger --test fss_108_counterfactual_branch_recompilation_contract -- "${s}" --exact --nocapture
done
e2e_finish
