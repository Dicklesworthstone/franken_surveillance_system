#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-036 (`fss-x4a.9.6`: retention/hold obligation tables).
# Exercises the conservative retention lattice, active-hold dominance over expiry, tombstoned hold
# release, differential naive lattice oracle across boundary timestamps, atomic FSSRHT01 persistence,
# plane/authority isolation, idempotency, conflict refusal, cancellation, and hostile wire decoding.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "retention_lattice_holds_tombstones_oracle_and_atomic_reload"
  echo "retention_hold_authority_conflicts_cancel_and_hostile_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-ledger \
  --test fss_036_retention_hold_tables_contract \
  -- --nocapture "$@"
