#!/usr/bin/env bash
# E2E proof driver for FSS-032 (fss-x4a.9.2): Qualify required FrankenSQLite APIs.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "qualifies_oracle_durable_and_merkle_adapters_with_honest_scope"
    "refuses_adversarial_broken_adapter_and_hostile_wire_certificates"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_032_frankensqlite_api_qualification"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-ledger --test fss_032_frankensqlite_api_qualification_contract -- "${s}" --exact --nocapture
done
e2e_finish
