#!/usr/bin/env bash
# E2E proof driver for SCHEMA-AGENT-QUERY-001 (fss-x4a.30.39): AgentQueryPlan (`fss.agent_query_plan.v1`).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "agent_query_plan_v1_canonical_binary_and_json_roundtrip"
    "agent_query_plan_v1_refuses_duplicates_neg_time_bad_json_and_hostile_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "schema_agent_query_plan_v1"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-core --test schema_agent_query_plan_v1_contract -- "${s}" --exact --nocapture
done
e2e_finish
