#!/usr/bin/env bash
# FSS-152 (`fss-x4a.23.2`) E2E verification: O(1) Arc-shared graph snapshot views, zero-copy
# concurrent isolation, ALG-BRIDGE-001 execution over pinned views, anchor/privacy/authority/
# revocation invalidation, and FSSGSV01 binary wire verification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_152_arc_snapshot_views.sh"
e2e_init "fss_152_arc_snapshot_views" "fss-x4a.23.2" "$@"
e2e_cargo_test "fss-graph-algorithms" "fss_152_arc_snapshot_views_contract"
e2e_summary
