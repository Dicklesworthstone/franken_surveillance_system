#!/usr/bin/env bash
# E2E proof driver for FSS-153 (fss-x4a.23.3): Canonical graph serialization & hash verification.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "canonical_graph_serialization_is_permutation_invariant_across_both_families"
    "canonical_graph_tamper_localization_cancel_and_hostile_wire_fail_closed"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_153_canonical_graph_serialization"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-graph-algorithms --test fss_153_canonical_graph_serialization_contract -- "${s}" --exact --nocapture
done
e2e_finish
