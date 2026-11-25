#!/usr/bin/env bash
# Canonical ATP transfer, path, and archive lifecycles (`fss-x4a.13.31`) E2E verification:
# 4-layer crosswalk & legacy spellings, root-last publication & non-collapsed counters,
# multipath request->drain->finalize cancellation, crash-cut framed journal replay parity,
# indeterminate reconciliation obligations, quarantine, and authority/version refusals.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_atp_lifecycles.sh"
e2e_init "fss_atp_lifecycles" "fss-x4a.13.31" "$@"
e2e_cargo_test "fss-object" "atp_lifecycle_contract"
e2e_summary
