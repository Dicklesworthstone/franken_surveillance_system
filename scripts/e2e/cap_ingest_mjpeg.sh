#!/usr/bin/env bash
# CAP- INGEST MJPEG frame splitter (fss-2h5zq.22).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_ingest_mjpeg.sh"
e2e_init "ingest_mjpeg" "fss-2h5zq.22" "$@"
e2e_cargo_test "fss-reference" "mjpeg_split_contract"
e2e_summary
