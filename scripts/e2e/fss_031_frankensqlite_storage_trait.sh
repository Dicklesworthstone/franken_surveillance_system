#!/usr/bin/env bash
# E2E proof driver for FSS-031 (fss-x4a.9.1): FrankenSQLite storage integration trait.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "storage_trait_proves_oracle_durable_and_merkle_equivalence_migrations_and_witnesses"
    "storage_trait_handles_crash_reconciliation_uncertified_absence_auth_cancel_and_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_031_frankensqlite_storage_trait"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-ledger --test fss_031_frankensqlite_storage_trait_contract -- "${s}" --exact --nocapture
done
e2e_finish
