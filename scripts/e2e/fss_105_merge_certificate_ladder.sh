#!/usr/bin/env bash
# FSS-105 (`fss-x4a.9.12`) E2E verification: three-rung intent-replay / structural / commutative
# merge certificate ladder composing FSS-103 witnesses, FSS-104 commit combiner, and FSSMC001 wire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_105_merge_certificate_ladder.sh"
e2e_init "fss_105_merge_certificate_ladder" "fss-x4a.9.12" "$@"
e2e_cargo_test "fss-ledger" "fss_105_merge_certificate_ladder_contract"
e2e_summary
