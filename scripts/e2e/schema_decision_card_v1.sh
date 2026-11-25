#!/usr/bin/env bash
# E2E proof driver for SCHEMA-DECISION-CARD-001 (fss-x4a.30.14): DecisionCardV1 (`fss.decision_card.v1`).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "decision_card_v1_canonical_binary_json_roundtrip_and_supersession"
    "decision_card_v1_refuses_clamp_bypass_malformed_json_and_hostile_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "schema_decision_card_v1"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-core --test schema_decision_card_v1_contract -- "${s}" --exact --nocapture
done
e2e_finish
