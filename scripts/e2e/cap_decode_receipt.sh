#!/usr/bin/env bash
# CAP- DECODE receipt/lineage (fss-2h5zq.42): custody-verified decode and refusal receipts on the
# checked-in MJPEG/JPEG fixtures, chunk tamper, custody mismatch, restart reopen, fresh-root rebuild.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_decode_receipt.sh"
e2e_init "decode_receipt" "fss-2h5zq.42" "$@"
e2e_cargo_test "fss-reference" "decode_receipt_contract"
e2e_summary
