#!/usr/bin/env bash
# FSS-133 (`fss-x4a.13.17`) E2E verification: graph-complete archive deletion traversal across
# all 9 artifact classes, evidence-hold and live-shared-parent blocking, adversarial hidden-ref
# leak detection, indeterminate remote deletion honesty, unknown external copies, and FSSDCL01 wire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_133_graph_complete_deletion.sh"
e2e_init "fss_133_graph_complete_deletion" "fss-x4a.13.17" "$@"
e2e_cargo_test "fss-object" "fss_133_graph_complete_deletion_contract"
e2e_summary
