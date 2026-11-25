#!/usr/bin/env bash
# FSS-131 (`fss-x4a.13.15`) E2E verification: archive replication-state and retrievability
# challenge ledger with non-collapsed custody ladder, freshness decay, repair obligations, and wire codec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_131_archive_replication_ledger.sh"
e2e_init "fss_131_archive_replication_ledger" "fss-x4a.13.15" "$@"
e2e_cargo_test "fss-object" "fss_131_archive_replication_ledger_contract"
e2e_summary
