#!/usr/bin/env bash
# scripts/e2e/cap_exec_scalar.sh
# End-to-end runner for CAP- EXEC scalar reference executor (fss-2h5zq.46) on the shared harness
# scripts/e2e/lib.sh (fss-2h5zq.1). It runs one cargo test target, scalar_executor_contract, remotely
# through rch; every CAPLOG record it prints (stdout or stderr) becomes one step of
# ${FSS_E2E_LOG_DIR:-target/e2e-logs}/exec_scalar/run_NNNN.log. --only <sel> and --only=<sel> select
# steps by name; CAPLOG steps are selected by their cargo target, scalar_executor_contract. Without
# lib.sh the script fails closed: there is no second, divergent harness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/lib.sh" ]]; then
    echo "Error: ${SCRIPT_DIR}/lib.sh (the fss-2h5zq.1 harness) is required; refusing to run without it" >&2
    exit 1
fi

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
e2e_init "exec_scalar" "fss-2h5zq.46" "$@"
e2e_cargo_test "fss-reference" "scalar_executor_contract"
e2e_summary
