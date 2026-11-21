#!/usr/bin/env bash
# FSS-132 (fss-x4a.13.16): Remote eventual-consistency and partial-list provider simulator e2e.
# Runs the deterministic oracle-parity, eventual-lag, stale-ghost, partial-list, conditional-put,
# multipart cold-restart, adversarial lying-provider, and 16-seed property campaign tests through
# the standard structured JSON-lines E2E harness.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_132_remote_simulator.sh"
e2e_init "fss_132_remote_simulator" "fss-x4a.13.16" "$@"
e2e_cargo_test "fss-object" "remote_eventual_consistency_contract"
e2e_summary
