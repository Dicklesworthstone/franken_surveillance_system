#!/usr/bin/env bash
# FSS-104 (`fss-x4a.9.11`) E2E verification: deterministic commit combiner and semantic SSI
# conflict oracle composing FSS-103 semantic witnesses with LedgerOracle and DurableReferenceLedger.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_104_commit_combiner_ssi.sh"
e2e_init "fss_104_commit_combiner_ssi" "fss-x4a.9.11" "$@"
e2e_cargo_test "fss-ledger" "fss_104_commit_combiner_ssi_contract"
e2e_summary
