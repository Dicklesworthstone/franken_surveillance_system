#!/usr/bin/env bash
# FSS-134 (`fss-x4a.13.18`) E2E verification: archive Decision Cards for path selection, GF(256)
# repair overhead sizing, and object chunk sizing with hard clamps, Pareto frontier, and FSSADC01 wire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_134_archive_decision_cards.sh"
e2e_init "fss_134_archive_decision_cards" "fss-x4a.13.18" "$@"
e2e_cargo_test "fss-object" "fss_134_archive_decision_cards_contract"
e2e_summary
