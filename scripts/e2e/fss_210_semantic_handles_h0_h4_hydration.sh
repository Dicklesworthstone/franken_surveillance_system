#!/usr/bin/env bash
# E2E proof driver for FSS-210 (fss-x4a.24.10): Semantic handles and bounded H0-H4 hydration.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "h3_source_evidence_and_h0_to_h4_progressive_hydration_contract"
    "h3_denies_missing_capability_privacy_degraded_completeness_and_tamper"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_210_semantic_handles_h0_h4_hydration"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-core --test fss_210_semantic_handles_h0_h4_hydration_contract -- "${s}" --exact --nocapture
done
e2e_finish
