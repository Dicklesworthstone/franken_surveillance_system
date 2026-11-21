#!/usr/bin/env bash
# CAP- LAB crash-matrix (fss-2h5zq.16):
# Runs the exhaustive crash-matrix and separate-process recovery contract test
# through the standard E2E harness, recording one CAPLOG step per fault row plus
# per-slug recovery verification steps.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_lab_crash_matrix.sh"
e2e_init "lab_crash_matrix" "fss-2h5zq.16" "$@"
e2e_cargo_test "fss-cli" "lab_crash_matrix_cli"
e2e_summary
