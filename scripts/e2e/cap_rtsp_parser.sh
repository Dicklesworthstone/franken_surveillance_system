#!/usr/bin/env bash
# scripts/e2e/cap_rtsp_parser.sh
# End-to-end verification for CAP- RTSP parser companion contract (fss-2h5zq.33).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LIB_SH="${SCRIPT_DIR}/lib.sh"
if [[ ! -f "${LIB_SH}" ]]; then
    echo "FAIL-CLOSED: ${LIB_SH} is absent (dependency fss-2h5zq.1 not yet merged)" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "${LIB_SH}"

SUITE_NAME="cap_rtsp_parser"
BEAD_ID="fss-2h5zq.33"

e2e_init "$SUITE_NAME" "$BEAD_ID" "$@"
e2e_cargo_test "fss-reference" "rtsp_parser_companion_contract"
e2e_summary
