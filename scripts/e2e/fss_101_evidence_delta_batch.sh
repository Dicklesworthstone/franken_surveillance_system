#!/usr/bin/env bash
# FSS-101 (`fss-x4a.9.8`) E2E verification: frozen `EvidenceDeltaBatch` v1 canonical
# ordering, anchor successor semantics, plane ownership, idempotency, crash-safe staging,
# and hand-audited `FSSBAT01` binary codec refusals (including allocation-bomb defenses).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_101_evidence_delta_batch.sh"
e2e_init "fss_101_evidence_delta_batch" "fss-x4a.9.8" "$@"
e2e_cargo_test "fss-ledger" "evidence_delta_batch_v1_contract"
e2e_summary
