#!/usr/bin/env bash
# CAP- scalar executor (fss-2h5zq.46).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_exec_scalar.sh"
e2e_init "exec_scalar" "fss-2h5zq.46" "$@"
e2e_cargo_test "fss-reference" "scalar_executor_contract"
e2e_summary
