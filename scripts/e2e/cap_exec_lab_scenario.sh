#!/usr/bin/env bash
# CAP- EXEC lab scenario (fss-2h5zq.52): `fss-lab run file-activity` on the recorded JPEG frames
# through the verified activity package; per-frame observations, receipt digests, single-source
# disposition and determinism across two roots (CAPLOG per observation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_exec_lab_scenario.sh"
e2e_init "exec_lab_scenario" "fss-2h5zq.52" "$@"
e2e_cargo_test "fss-cli" "lab_file_activity_cli"
e2e_summary
