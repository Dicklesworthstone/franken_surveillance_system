#!/usr/bin/env bash
# E2E proof driver for FSS-033 (fss-x4a.9.3): Implement ledger schema/migrations.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "migrates_live_v1_journal_to_v2_epochs_with_merkle_proofs_and_idempotency"
    "cancellation_corrupt_source_target_conflict_and_hostile_wire_fail_closed"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_033_ledger_schema_migrations"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-ledger --test fss_033_ledger_schema_migrations_contract -- "${s}" --exact --nocapture
done
e2e_finish
