#!/usr/bin/env bash
# FSS-126 (`fss-x4a.13.10`) E2E verification: ATP transfer receipt (`fss.transfer_receipt.v1`)
# schema conformance and crash-resumable on-disk framed journal v1 across multi-restart
# checkpoints, indeterminate obligations, and hostile disk faults (symlink, truncation, corruption).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_126_transfer_receipt_journal.sh"
e2e_init "fss_126_transfer_receipt_journal" "fss-x4a.13.10" "$@"
if [[ "${_E2E_LIST:-0}" -eq 1 ]]; then
  e2e_cargo_test "fss-object" "fss_126_transfer_receipt_journal_contract"
  e2e_summary
  exit 0
fi
RECEIPT_DIR="$(e2e_tmpdir)"
FSS_126_EMIT_RECEIPT_DIR="${RECEIPT_DIR}" e2e_cargo_test "fss-object" "fss_126_transfer_receipt_journal_contract"
for receipt in "${RECEIPT_DIR}/archive_complete.json" "${RECEIPT_DIR}/semantic_complete.json" "${RECEIPT_DIR}/indeterminate.json"; do
  python3 "${SCRIPT_DIR}/../json_instance_validate.py" "${SCRIPT_DIR}/../../schemas/transfer_receipt.v1.json" "${receipt}"
done
e2e_summary
