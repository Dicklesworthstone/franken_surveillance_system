#!/usr/bin/env bash
# E2E proof driver for SCHEMA-AGENT-WORKSPACE-001 (fss-x4a.30.31): SessionCapsule (`fss.agent_session_capsule.v1`).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "session_capsule_v1_roundtrips_binary_json_and_enforces_immutable_supersession"
    "session_capsule_v1_refuses_hostile_json_debt_schema_and_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "schema_agent_session_capsule_v1"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-core --test schema_agent_session_capsule_v1_contract -- "${s}" --exact --nocapture
done
e2e_finish
