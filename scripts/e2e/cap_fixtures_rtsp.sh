#!/usr/bin/env bash
# scripts/e2e/cap_fixtures_rtsp.sh
# End-to-end integration test runner for CAP- fixtures RTSP transcript companion contract (fss-2h5zq.8).
# Conforms to the CAP- structured JSON-lines logging specification via scripts/e2e/lib.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fails closed if lib.sh is absent (prerequisite fss-2h5zq.1 not merged yet)
if [[ ! -f "${SCRIPT_DIR}/lib.sh" ]]; then
    echo "FAIL CLOSED: scripts/e2e/lib.sh is absent (prerequisite fss-2h5zq.1 not merged yet)" >&2
    exit 1
fi

# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

e2e_init "fixtures_rtsp" "fss-2h5zq.8" "$@"
e2e_cargo_test "fss-reference" "media_fixture_rtsp_contract"
e2e_summary
