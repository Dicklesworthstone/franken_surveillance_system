#!/usr/bin/env bash
# CAP- DECODE lab command (fss-2h5zq.44): `fss-lab decode` per fixture against the goldens,
# determinism across two roots, the truncated-last degraded case and receipted refusals.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_lab_decode.sh"
e2e_init "lab_decode" "fss-2h5zq.44" "$@"
e2e_cargo_test "fss-cli" "lab_decode_cli"
e2e_summary
