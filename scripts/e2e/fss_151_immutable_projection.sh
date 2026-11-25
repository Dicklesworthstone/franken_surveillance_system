#!/usr/bin/env bash
# FSS-151 (`fss-x4a.23.1`) E2E verification: immutable graph projection and generational-handle core
# across all 12 registered FSS graph universes, capability/privacy pre-filtering, CSR bridge into
# ALG-BRIDGE-001, stale-handle refusal, and FSSGPR01 binary wire verification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_151_immutable_projection.sh"
e2e_init "fss_151_immutable_projection" "fss-x4a.23.1" "$@"
e2e_cargo_test "fss-graph-algorithms" "fss_151_immutable_projection_contract"
e2e_summary
