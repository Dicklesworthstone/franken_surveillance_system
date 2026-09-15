#!/usr/bin/env bash
# scripts/e2e/cap_ingest_mjpeg.sh
# End-to-end runner for CAP- INGEST MJPEG frame splitter (fss-2h5zq.22) on the shared harness
# scripts/e2e/lib.sh (fss-2h5zq.1). It runs one cargo test target, mjpeg_split_contract, remotely
# through rch; every CAPLOG record it prints becomes one step of
# ${FSS_E2E_LOG_DIR:-target/e2e-logs}/ingest_mjpeg/run_NNNN.log.
#
# Usage: scripts/e2e/cap_ingest_mjpeg.sh [--list] [--only mjpeg_split_contract]
# CAPLOG steps are selected through their cargo target name; a failing run prints its repro.
# Without lib.sh the script fails closed: there is no second, divergent harness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/lib.sh" ]]; then
    echo "Error: ${SCRIPT_DIR}/lib.sh (the fss-2h5zq.1 harness) is required; refusing to run without it" >&2
    exit 1
fi

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
e2e_init "ingest_mjpeg" "fss-2h5zq.22" "$@"
e2e_cargo_test "fss-reference" "mjpeg_split_contract"
e2e_summary
