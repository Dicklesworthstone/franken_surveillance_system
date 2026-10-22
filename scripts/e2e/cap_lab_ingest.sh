#!/usr/bin/env bash
# CAP- INGEST command (fss-2h5zq.18): the LAB ingest command was superseded by the product
# command `fss-file import` (fss-2h5zq.17); this script runs the `fss-file import` contract
# tests (crates/fss-cli/tests/lab_ingest_cli.rs) through the standard e2e harness.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_lab_ingest.sh"
e2e_init "lab_ingest" "fss-2h5zq.18" "$@"
e2e_cargo_test "fss-cli" "lab_ingest_cli"
e2e_summary
