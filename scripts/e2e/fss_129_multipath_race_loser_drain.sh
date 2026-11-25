#!/usr/bin/env bash
# FSS-129 (`fss-x4a.13.13`) E2E verification: multipath transfer race, hard integrity/privacy/
# residency/cost policy clamps (XFER-INV-007), diverse-domain hedging, corrupt-winner quarantine,
# mandatory loser drain with zero leaked sockets/temps/billing ops (XFER-INV-008), and FSSMP001 wire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_129_multipath_race_loser_drain.sh"
e2e_init "fss_129_multipath_race_loser_drain" "fss-x4a.13.13" "$@"
e2e_cargo_test "fss-object" "fss_129_multipath_race_loser_drain_contract"
e2e_summary
