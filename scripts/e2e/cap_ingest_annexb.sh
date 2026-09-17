#!/usr/bin/env bash
# CAP- INGEST Annex B splitter (fss-2h5zq.20).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_ingest_annexb.sh"
e2e_init "ingest_annexb" "fss-2h5zq.20" "$@"
e2e_cargo_test "fss-reference" "annexb_split_contract"
e2e_summary
