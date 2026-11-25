#!/usr/bin/env bash
# FSS-107 (`fss-x4a.9.14`) E2E verification: derived high-water protocol for graph, search,
# model, and projection caches with generation pinning, incremental catch-up, and rebuild gates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_107_derived_high_water.sh"
e2e_init "fss_107_derived_high_water" "fss-x4a.9.14" "$@"
e2e_cargo_test "fss-ledger" "fss_107_derived_high_water_contract"
e2e_summary
