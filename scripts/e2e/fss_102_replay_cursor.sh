#!/usr/bin/env bash
# FSS-102 (`fss-x4a.9.9`) E2E verification: single-thread reference delta ledger and
# anchor-pinned bounded LedgerReplayCursor across LedgerOracle and DurableReferenceLedger.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_102_replay_cursor.sh"
e2e_init "fss_102_replay_cursor" "fss-x4a.9.9" "$@"
e2e_cargo_test "fss-ledger" "fss_102_replay_cursor_contract"
e2e_summary
