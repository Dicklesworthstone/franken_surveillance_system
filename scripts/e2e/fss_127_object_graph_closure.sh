#!/usr/bin/env bash
# FSS-127 (`fss-x4a.13.11`) E2E verification: deterministic ATP object-graph closure verifier
# with authority-before-expansion, non-collapsed custody floors, bottom-up canonical post-order,
# and cycle/tombstone/invalidation/indeterminate/cancel/budget/wire fault refusals.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_127_object_graph_closure.sh"
e2e_init "fss_127_object_graph_closure" "fss-x4a.13.11" "$@"
e2e_cargo_test "fss-object" "fss_127_object_graph_closure_contract"
e2e_summary
