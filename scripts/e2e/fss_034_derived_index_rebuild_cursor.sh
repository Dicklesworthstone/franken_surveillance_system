#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-034 (`fss-x4a.9.4`: derived-index rebuild cursor).
# Exercises crash-resumable page-by-page derived secondary index rebuilds over both v1
# DurableReferenceLedger and migrated v2 MerkleEpochLedger, automatic genesis reset on
# DerivedGenerationPin drift, differential oracle equivalence, pending-append pause, and FSSDIC01 wire checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "resumable_paged_rebuild_matches_full_genesis_on_v1_and_v2_and_resets_on_drift"
  echo "rebuild_cursor_pending_cancel_budget_auth_and_hostile_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-ledger \
  --test fss_034_derived_index_rebuild_cursor_contract \
  -- --nocapture "$@"
