#!/usr/bin/env bash
# E2E proof driver for FSS-162 (fss-x4a.23.12): Capability-projected factorized graph-relational query planner.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "factorized_planner_matches_reference_oracle_is_order_invariant_and_honors_redaction"
    "factorized_planner_refuses_invalid_queries_cancel_and_hostile_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_162_factorized_query_planner"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-graph-algorithms --test fss_162_factorized_query_planner_contract -- "${s}" --exact --nocapture
done
e2e_finish
